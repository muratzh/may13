import assert from 'assert'
import {
  User,
  AuthToken,
  Workspace,
  Invitation,
  Membership,
  AccessKey,
  Session,
  OrganizationRoles,
} from '../data/models'
import { validationResult } from 'express-validator'
import { Status } from '../data/models/status'
import { Role } from '../data/models/roles'
import { getMembership, retrieveUser, setUserSession, destroyUserSessions } from '../data/util/user.util'
import { Op } from 'sequelize'
import { asyncHandler, ApiError, isDuplicateKeyError } from '../utils'
import conf from '../../config'
import notification from '../notification/Notification'


const API_VIEW_FIELDS = [
  'id',
  'username',
  'email',
  'firstName',
  'lastName',
  'fullName',
  'imageUrl',
  'company',
  'settings',
  'membership',
  'loginTypes',
]

export const invitationLink = (invitation) => {
  return `${conf.baseUrl}/signup/${invitation.token}`
}

export const apiView = (user) => {
  user = _.pick(user, API_VIEW_FIELDS)
  const { membership } = user
  // using array since current system allows for multiple memberships,
  // but only actually recognizes one
  user.membership = [
    {
      ..._.pick(membership, ['role', 'status', 'onboarding']),
      ..._.pick(membership.workspace, [
        'repoId',
        'company',
        'plan',
        'settings',
      ]),
      workspace: membership.workspace.id,
      // allows for non-mandatory access key sending (ie. for workspace members)
      accessKey:
        membership.workspace.accessKey && membership.workspace.accessKey.token,
    },
  ]
  return user
}

export const sessionInfo = (req) => {
  const now = new Date();
  return {
    session: {
      expires: req.session ? Date.parse(req.session.cookie._expires) - now : 0
    }
  }
}

const validateAccessKey = async (req) => {
  req.role = null

  // Extract auth token from header
  const authHeader = req.get('authorization')
  if (_.isUndefined(authHeader)) {
    throw new ApiError('Missing authorization header', 401)
  }
  const str = _.split(authHeader, ' ', 2)
  if (_.get(str, 0) !== 'Bearer') {
    throw new ApiError('Only bearer authentication supported', 401)
  }
  const token = _.get(str, 1)

  const accessKey = await AccessKey.findOne({
    where: {
      token: token,
    },
  })

  let userId = undefined
  if (!accessKey) {
    // @todo, @note: Searching for token inside the session table. This is authz side fix for handling calling of fiddler API in exectuor service with API token. This wild card search in session table may not be a performance issue in single org cluster, but will need to be properly fixed
    const sessionAccessKey = await Session.findOne({
      where: {
        data: { [Op.like]: `%${token}%` }
      },
      attributes: ['sid', 'expires', 'data']
    })
    if (!sessionAccessKey) {
      throw new ApiError('Invalid token')
    } else {
      const sessionDetails = JSON.parse(sessionAccessKey.data)
      userId = sessionDetails.user.id
    }
  } else {
    userId = accessKey.userId
  }

  const user = await retrieveUser({
    where: {
      id: userId,
    },
  })

  if (user) {
    //@todo: Is this the best place to set these variables?
    req.role = user.role
    req.orgId = user.orgId
    req.userId = user.id
    req.workspace = user.membership.workspaceId
    req.membershipDetails = user.membership
    req.userFullName = user.fullName
    return true
  } else {
    throw new ApiError('User with token not found')
  }
}


export const getUserAuth = async (req) => {
  let userAuth = {
    isAuthenticated: false,
    authType: "session",
    token: undefined,
  }
  if (req.user) { // Passport sets req.user if authentication was successful
    userAuth.isAuthenticated = true
  } else if (req.get('authorization')) { // Checking for accesskey and it's validity for token auth.
    let accessKey = req.get('authorization')
    userAuth.authType = "token"
    userAuth.token = accessKey

    try {
      userAuth.isAuthenticated = await validateAccessKey(req)
    } catch (e) {
      console.log(e)
    }
  }

  return userAuth
}

export const checkAuth = ({ required } = { required: false }) => async (
  req,
  res,
  next
) => {

  let userAuth = await getUserAuth(req)

  if (!userAuth.isAuthenticated) {
    if (required) {
      return next(new ApiError(`Authentication required`, 401))
    }
    return next()
  }
  // Temporary fix for membership verification in auth token authentication
  if (req.session.user) {
    if (!req.session.user.membership) {
      // @todo: in case of auth token we don't have session so we should set all the user details not in session but outside.
      if (required) {
        return next(new ApiError('Account not a member of any workspace', 403))
      }
      return next()
    }
  }
  else {
    if (!req.membershipDetails) {
      if (required) {
        return next(new ApiError('Account not a member of any workspace', 403))
      }
      return next()
    }
  }
  next()
}

export const requireAuth = checkAuth({ required: true })

export const emailValidationError = (req, res,next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Invalid email address', errors: errors.array() });
  }
  next()
}

export const getPasswordSafetyError = (password) => {
  if (password.length < 12) {
    return new ApiError('Password must be at least 12 characters long.')
  }
  if (password.toUpperCase() === password) {
    return new ApiError('Password must contain a lowercase character.')
  }
  if (password.toLowerCase() === password) {
    return new ApiError('Password must contain an uppercase character.')
  }
  if (!/[^a-zA-Z\-\/]/.test(password)) {
    return new ApiError(
      'Password must contain a number and a special character.'
    )
  }
}

export const expireAllUserApiTokens = (workspaceId, userId) => {
  return AccessKey.destroy({
    where: {
      userId,
    },
  })
}

export const login = asyncHandler(async (req, res, next) => {
  if (!(conf.env === 'onebox' && process.env.AUTH_TOKEN)) {
    // Checking for Captcha, avoiding unnecessary calls to DB
    // @todo: where are we using captcha, if not remove
    if (req.passedCaptcha === false && req.firstCaptcha !== true) {
      await new Promise((resolve) =>
        setTimeout(resolve, (Math.floor(Math.random() * 3) + 2) * 1000)
      )
      return res.status(429).json({
        message: 'Invalid captcha, email, and/or password combination.',
        captchaSvg: req.captchaSvg,
      })
    }
  }

  try {
    const user = await retrieveUser({ where: { email: req.user.email.full } })

    // status must be active
    const membership = user.membership
    if (!membership || membership.status !== Status.ACTIVE) {
      // @todo: come up with consistent naming convention
      return next(new ApiError('Not an active workspace member', 403))
    }

    await setUserSession(req, user)

    res.json({ user: apiView(user), ...sessionInfo(req) })
  } catch (e) {
    next(e)
  }
})

export const logout = async (req, res, next) => {
  try {
    req.session.destroy()
    req.logout()
    res.json({})
  } catch (e) {
    next(e)
  }
}

export const user = (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate')
  res.json({
    user: req.session.user ? apiView(req.session.user) : null,
    ...sessionInfo(req)
  })
}

export const forgotPassword = asyncHandler(async (req, res, next) => {
  const { email, dontSend } = req.body

  const token = await AuthToken.create({
    ip: req.ip,
    ua: req.get('user-agent'),
  })

  try {
    let [rowsUpdate, [user]] = await User.update(
      {
        resetToken: token.id,
      },
      {
        where: {
          email,
        },
        returning: true,
      }
    )
    if (rowsUpdate === 0) {
      // for security reasons we always send status 200
      return res.json({ email })
    }
    user = user.raw()
    const membership = await getMembership(user)
    if (!membership || membership.status !== Status.ACTIVE) {
      // for security reasons we always send status 200
      return res.json({ email })
    }
    if (dontSend) {
      // skip sending email for testing purposes
      return res.json({ email, sent: false })
    }
    const { repoId } = await Workspace.findByPk(membership.workspace.id, {
      attributes: ['repoId'],
    })
    const link = `${conf.baseUrl}/reset-password/${token.id}`
    notification.sendEmail(
      'forgot-password',
      {
        link: link,
        email,
      },
      {
        to: email,
        from: conf.adminNoReplyEmail,
      },
      repoId
    )
    console.log(
      'forgot-password URL requested by', `${user.username}`
    )
    res.json({ email })
  } catch (e) {
    next(e)
  }
})

export const resetPassword = async (req, res, next) => {
  const { token, password } = req.body

  let error = getPasswordSafetyError(password)
  if (error) {
    return next(error)
  }

  // 12 hrs token expiration
  const RESET_TOKEN_TTL_MS = 12 * 60 * 60 * 1000

  try {
    let [numUpdated, [user]] = await User.update(
      {
        resetToken: null,
      },
      {
        where: {
          resetToken: token,
        },
        returning: true,
      }
    )

    let authToken = await AuthToken.findOne(
      {
        where: {
          id: token,
          createdAt: {
            [Op.gt]: new Date(Date.now() - RESET_TOKEN_TTL_MS),
          },
        },
      },
      {
        raw: false,
      }
    )

    if (!authToken) {
      await user.save() // save without new password
      throw new ApiError('Invalid or expired password reset request.')
    } else {
      await authToken.destroy()
      user.passwordHash = User.hashPassword(password)
      await user.save()

      // authenticate session
      const userDetails = await retrieveUser({
        where: {
          id: user.id,
        },
      })

      // @calling passport login to set appropriate sessions
      const passportUser = {
        name: {
          first: user.firstName,
          last: user.lastName
        },
        email: user.email,
        tokens: undefined
      }
      req.logIn(passportUser, function (err) {
        if (err) { return next(err); }
        setUserSession(req, userDetails)
        return res.json({ user: apiView(userDetails), ...sessionInfo(req) })
      })

    }
  } catch (e) {
    next(e)
  }
}

const checkUserRole = async (requestedRole, currentUserRole) => {

  if (!requestedRole) {
    throw new ApiError('Request body missing key \'role\'', 422)
  }
  if (Object.values(Role).indexOf(requestedRole) === -1) {
    throw new ApiError(`'${requestedRole}' is an invalid role`, 400)
  }
  if (currentUserRole === Role.MEMBER) {
    throw new ApiError("A MEMBER cannot invite/update an user", 401)
  }
  if (requestedRole === Role.SUPER_ADMIN && currentUserRole !== Role.SUPER_ADMIN) {
    throw new ApiError("Only a SUPER ADMIN user can invite/update an user to be a SUPER ADMIN", 401)
  }

}

export const inviteMember = asyncHandler(async (req, res, next) => {

  const { email } = req.body
  const invitedUserRole = req.body.role
  let workspaceId, orgName, userRole, fullName
  if (req.session.user) {
    workspaceId = req.session.user.membership.workspace.id
    orgName = req.session.user.membership.workspace.repoId
    userRole = req.session.user.role
    fullName = User.fullName(req.session.user)
  }
  else {
    workspaceId = req.workspace
    orgName = req.orgId
    userRole = req.role
    fullName = req.userFullName
  }

  await checkUserRole(invitedUserRole, userRole)

  const existingUser = await User.findOne({ where: { email } })

  if (existingUser) {
    const existingMembership = await getMembership(existingUser)
    if (existingMembership) {
      // @TODO support single user part of multiple orgs - && workspaceId === existingMembership.workspace.id.
      throw new ApiError('A user with the given email already exists. Please contact your administrator.')
    }
  }

  const existingInvitation = await Invitation.findOne({
    where: {
      email: email,
    },
  })
  if (existingInvitation) {
    throw new ApiError('An invitation for the user already exists')
  }

  const invitation = await Invitation.create({
    workspaceId: workspaceId,
    email: email,
    role: invitedUserRole,
    type: 'member-invite',
  })

  if (invitation) {
    const link = invitationLink(invitation)
    // we don't wait
    notification.sendEmail(
      'invite-member',
      {
        link,
        inviterEmail: email,
        inviterName: fullName,
      },
      {
        to: email,
        from: conf.adminNoReplyEmail,
      },
      orgName
    )
    console.log(
      'invitation URL sent to:', `${email}`
    )
    res.json({
      member: {
        email: email,
        membership: [{ role: invitedUserRole, status: 'invited' }],
        link: `${conf.baseUrl}/signup/${invitation.token}`,
      },
    })
  }
})

export const revokeInvitation = asyncHandler(async (req, res, next) => {

  const { email } = req.body
  // @TODO should revoking of a super-admin invitation be restricted to super-admin user?
  if (req.session.user.role === Role.MEMBER) {
    throw ApiError('Member cannot revoke an invitation', 401)
  }
  // We no longer check for user as doing that means if an invitation is pending in their name then we cannot revoke in pevious implementation. More about the issue here. https://fiddlerlabs.atlassian.net/browse/FNG-2809
  try {
    await Invitation.destroy({
      where: {
        email,
      },
    })
    res.json({
      member: {
        email
      }
    })
  } catch (e) {
    throw e
  }

})

export const updateInvitation = asyncHandler(async (req, res, next) => {

  const { email } = req.body
  const updatedUserRole = req.body.role

  const existingUser = await User.findOne({
    where: {
      email: email,
    },
  })
  if (existingUser) {
    const existingMembership = await getMembership(existingUser)
    if (
      existingMembership &&
      req.workspace === existingMembership.workspaceId
    ) {
      throw new ApiError('Already a member')
    }
  }

  await checkUserRole(updatedUserRole, req.session.user.role)

  let invitation = await Invitation.findOne({
    where: {
      email: email,
    },
  })
  if (!invitation) {
    throw new ApiError('Invitation invalid or expired')
  }
  invitation.role = updatedUserRole
  await invitation.save()

  res.json({
    member: {
      email,
      membership: [{ role: updatedUserRole, status: 'invited' }],
    },
  })
})

export const getInvitationInfo = asyncHandler(async (req, res, next) => {
  const { token } = req.params
  const invitation = await Invitation.findOne(
    {
      where: {
        token,
      },
      include: [
        {
          model: Workspace,
          attributes: ['repoId', 'company'],
        },
      ],
    },
    {
      nest: true, // prevents flattening of workspace, queries raw by default
    }
  )

  if (!invitation) {
    throw new ApiError('Invalid or expired invitation')
  }

  // ignoring Sequelize's stubborn way of aliasing associated models
  invitation.workspace = invitation.Workspace

  res.json({
    workspace: invitation.workspace.repoId,
    company: invitation.workspace.company,
    email: invitation.email,
    type: invitation.type,
  })
})

export const signupInvited = asyncHandler(async (req, res, next) => {
  try {
    const { password, firstName, lastName, company, token } = req.body

    let error = getPasswordSafetyError(password)
    if (error) {
      throw error
    }

    const invitation = await Invitation.findOne(
      {
        where: {
          token,
        },
      },
      {
        raw: false,
      }
    )

    if (!invitation) {
      throw new ApiError('Invalid or expired invitation')
    }

    const organization = await Workspace.findByPk(invitation.workspaceId, {
      raw: false,
    })

    const { role, email, type } = invitation.raw()

    const username = email

    let user = await User.create({
      email: email || '',
      username: username || '',
      passwordHash: User.hashPassword(password),
      firstName,
      lastName,
      ip: req.ip,
      ua: req.get('user-agent'),
    }).catch((err) => {
      if (isDuplicateKeyError(err)) {
        err = new ApiError('Email already exists.', 409)
      }
      throw err
    })

    const orgRole = await OrganizationRoles.create({
      name: role,
      user_id: user.id,
      organization_id: organization.id,
    })

    const membership = await Membership.create({
      userId: user.id,
      workspaceId: organization.id,
      ...(type === 'promo-code' && { onboarding: '{ show: true }' }),
    })

    // revoke invitation
    await invitation.destroy()

    // @todo: we should update the company in workspace only if not present.
    if (company && !organization.company) {
      organization.company = company
      await organization.save()
    }

    // retrieve to ensure canonical user object is returned
    const userDetails = await retrieveUser({
      where: {
        id: user.id,
      },
    })



    // @calling passport login to set appropriate sessions
    const passportUser = {
      name: {
        first: user.firstName,
        last: user.lastName
      },
      email: user.email,
      tokens: undefined
    }
    req.logIn(passportUser, function (err) {
      if (err) { return next(err); }
      setUserSession(req, userDetails)
      return res.json({ user: apiView(userDetails), ...sessionInfo(req) })
    })

  } catch(e) {
    next(e)
  }
})

export const acceptInvitation = (req, res, next) => {
  assert.ok(req.user)
  // TODO
}

export const workspaceMembers = async (req, res, next) => {
  assert.ok(req.user)
  assert.ok(req.session.user.membership.workspace)

  try {
    let memberships = await Membership.findAll(
      {
        where: {
          workspaceId: req.session.user.membership.workspace.id,
        },
        attributes: ['userId'],
      },
      {
        raw: true,
      }
    )

    const invitations = await Invitation.findAll({
      where: {
        workspaceId: req.session.user.membership.workspace.id,
      },
    })

    const users = await Promise.all(
      memberships.map(
        async (membership) =>
          await retrieveUser({
            where: {
              id: membership.userId,
            },
          })
      )
    )

    res.json({
      members: [
        ...users
          .filter((user) => user !== null) // ensure membership applies to exisiting user
          .map((user) => {
            // needed to fit into apiView expectation
            const { membership } = user
            return {
              ...apiView(user),
              membership: [membership],
            }
          }),
        ...invitations.map((invitation) => {
          return {
            email: invitation.email,
            membership: [
              {
                role: invitation.role,
                status: 'invited',
              },
            ],
            link: invitationLink(invitation)
          }
        }),
      ],
    })
  } catch (e) {
    next(e)
  }
}

// Access Keys
export const fetchAccessKeys = (req, res, next) => {
  assert.ok(req.user)
  assert.ok(req.session.user.membership.workspace)

  AccessKey.findAll({
    where: {
      workspaceId: req.session.user.membership.workspace.id,
      type: 'sdk',
    },
  })
    .then(async (keys) => {
      // this isn't great or efficient, but the frontend expects nested membership
      // TODO: avoid doing these nested queries when the frontend/apiView stops
      // expecting the document model
      await Promise.all(
        keys.map(
          async (key) =>
          (key.user = await retrieveUser({
            where: {
              id: key.userId,
            },
          }))
        )
      )
      keys = _.filter(keys, (key) => key.type === 'sdk' && key.user != null) // verify that user still exists

      // req.authorized comes from authz middleware
      if (!req.authorized) {
        keys = _.filter(keys, (key) => key.user.id === req.session.user.id)
      }

      res.json({
        accessKeys: [
          ...keys.map((key) => {
            return {
              token: key.token,
              user: apiView(key.user),
              createdAt: key.createdAt,
              lastUsed: key.lastUsed,
            }
          }),
        ],
      })
    })
    .catch(next)
}

export const createAccessKey = (req, res, next) => {
  assert.ok(req.user)
  assert.ok(req.session.user.membership.workspace.id)

  //@todo: This is where it needs to change to support multiple api keys in sdk
  AccessKey.findOrCreate({
    where: {
      workspaceId: req.session.user.membership.workspace.id,
      userId: req.session.user.id,
      type: 'sdk',
    },
  })
    .then(([key, created]) => {
      if (!created) {
        throw new ApiError('Key already exists', 409)
      }
      const { token, createdAt, lastUsed } = key
      res.json({
        //@todo: check how this plays out what is req.user
        accessKey: { token, createdAt, lastUsed, user: apiView(req.session.user) },
      })
    })
    .catch(next)
}

export const deleteAccessKey = async (req, res, next) => {
  assert.ok(req.user)
  assert.ok(req.session.user.membership.workspace.id)

  let { userId } = req.body

  // delete another member's key - must be admin
  if (!req.session.user.id === userId && !req.authorized) {
    throw new ApiError('Insufficient permissions', 403)
  }

  if (!userId) {
    // delete own key
    userId = req.session.user.id
  }

  try {
    // remove relevant access key/s
    let key = await AccessKey.findOne({
      where: {
        workspaceId: req.session.user.membership.workspace.id,
        userId,
        type: 'sdk',
      },
    })

    if (!key) {
      throw new ApiError('No access keys exist for user', 401)
    }

    const { token } = key

    await key.destroy()

    res.json({ accessKey: { token } })
  } catch (e) {
    next(e)
  }
}

export const userByAccessKey = async (req, res, next) => {
  const { accessKey } = req.params

  try {
    const key = await AccessKey.findOne({
      where: {
        token: accessKey,
      },
    })
    if (!key) {
      throw new ApiError('Invalid access key', 401)
    }
    const user = await retrieveUser(
      {
        where: {
          id: key.userId,
        },
      },
      key.workspaceId
    )
    res.json({
      user: {
        ..._.pick(user, API_VIEW_FIELDS),
        membership: {
          ..._.pick(user.membership, ['status']),
          workspaceId: _.pick(user.membership.workspace, ['id', 'repoId']),
        },
      },
      accessKey: _.pick(key, ['createdAt', 'type']),
    })
  } catch (e) {
    next(e)
  }
}

export const updateOnboarding = async (req, res, next) => {
  assert.ok(req.user)
  assert.ok(req.session.user.membership.workspace.id)


  try {
    let membership = await Membership.findOne(
      {
        where: {
          userId: req.session.user.id,
          workspaceId: req.session.membership.workspace.id,
        },
      },
      {
        raw: false,
      }
    )
    //@todo: the below can be security issue without inspecting what is there in body, to check later
    membership.onboarding = req.body
    await membership.save()
    const user = await retrieveUser(
      {
        where: {
          id: req.session.user.id,
        },
      },
      req.session.membership.workspace.id,
    )
    res.json({ user: apiView(user) })
  } catch (e) {
    next(e)
  }
}

export const updateMembership = async (req, res, next) => {
  assert.ok(req.user)
  assert.ok(req.session.user.membership.workspace.id)

  const { userId } = req.params
  const updatedUserRole = req.body.role
  const workspaceId = req.session.user.membership.workspace.id
  const repoId = req.session.user.membership.workspace.repoId

  try {
    await checkUserRole(updatedUserRole, req.session.user.role)

    let membership = await Membership.findOne({
      where: {
        userId: userId
      }
    })
    if (!membership) {
      throw new ApiError('User not found or not a workspace member.', 404)
    }

    // @todo: The below is an issue when a user can belong to multiple orgs. Currently is ok as we support only one user one org.
    let orgRole = await OrganizationRoles.findOne({
      where: {
        user_id: userId
      }
    })

    // The below condition is to check if the user is already a SUPER_ADMIN user
    if (orgRole.name === Role.SUPER_ADMIN && req.session.user.role !== Role.SUPER_ADMIN) {
      throw new ApiError('You have to be a SUPER ADMIN to update role of SUPER ADMIN user', 401)
    }

    let emailType = ''
    if (updatedUserRole === Role.DEACTIVATED) {
      membership.status = Status.DEACTIVATED
      // remove access keys
      await AccessKey.destroy({
        where: {
          workspaceId: workspaceId,
          userId: userId,
        },
      })

      await destroyUserSessions(userId)

      emailType = 'user-deactivated'

    } else if (membership.status === Status.DEACTIVATED) {
      //@question: Why is this condition there? If the idea, is this endpoint called from a different place with different set of inputs.
      membership.status = Status.ACTIVE
      emailType = 'user-activated'

    }

    const user = await User.findByPk(userId)
    // notify only for Activation or Deactivation
    if (emailType !== '') {
      notification
        .sendEmail(
          emailType,
          { workspaceId: repoId },
          { to: user.email, from: conf.adminNoReplyEmail },
          repoId
        )
        .catch((err) => console.log(`Unable to send '${emailType}' email`, err))
    }

    await membership.save()

    // update roles for user
    orgRole.name = updatedUserRole
    await orgRole.save()

    res.json({
      member: {
        ...apiView(
          await retrieveUser({
            where: {
              id: userId,
            },
          })
        )
      },
    })
  } catch (e) {
    next(e)
  }
}

export const updateUserInfo = async (req, res, next) => {
  assert.ok(req.user)

  const setter = _.pick(req.body, [
    'firstName',
    'lastName',
    'email',
    'settings',
    'password',
    'imageUrl',
  ])

  try {
    if (setter.password) {
      const { curPassword = '' } = req.body
      const userDetails = await User.findOne({
        where: {
          email: req.user.email.full
        }
      })
      if (!(await User.authenticate(userDetails, curPassword))) {
        throw new ApiError('Incorrect current password. Password not changed.')
      }
      if (curPassword === setter.password) {
        throw new ApiError('New password must be different from current one.')
      }
      let error = getPasswordSafetyError(setter.password)
      if (error) {
        throw error
      }
      setter.passwordHash = User.hashPassword(setter.password)
    }
    if (setter.settings) {
      // support settings-level selective update
      setter.settings = {
        ...req.session.user.settings,
        // disallow changes to account-related notifications
        ..._.omit(setter.settings, 'notifyAccount'),
      }
    }
    if (setter.email) {
      setter.email = setter.email.toLowerCase()
    }
    if(setter.firstName){
      setter.firstName = setter.firstName.trim()
    }
    if(setter.lastName){
      setter.lastName = setter.lastName.trim()
    }
    let [numUpdated, users] = await User.update(setter, {
      where: {
        id: req.session.user.id,
      },
      returning: true,
    })

    let updatedRecord = await retrieveUser({
      where: {
        id: req.session.user.id,
      },
    })

    // revoke existing sessions if email or password changed
    if (setter.passwordHash || setter.email) {
      await destroyUserSessions(req.session.user.id)

      // @calling passport login to set appropriate sessions
      const passportUser = {
        name: {
          first: updatedRecord.firstName,
          last: updatedRecord.lastName
        },
        email: updatedRecord.email,
        tokens: undefined
      }
      req.logIn(passportUser, function (err) {
        if (err) { return next(err); }
        setUserSession(req, updatedRecord)
        return res.json({ user: apiView(updatedRecord), ...sessionInfo(req) })
      })
    }
    else {
      setUserSession(req, updatedRecord)

      res.json({ user: apiView(updatedRecord), ...sessionInfo(req) })
    }

  } catch (err) {
    if (isDuplicateKeyError(err)) {
      err = new ApiError('Email already exists.', 409)
    }
    next(err)
  }
}

export const updateWorkspaceSettings = asyncHandler(async (req, res, next) => {
  assert.ok(req.user)
  assert.ok(req.session.user.membership.workspace)

  try {
    const workspace = await Workspace.findByPk(req.session.user.membership.workspace.id, { raw: false })
    workspace.settings = {
      ...workspace.settings,
      ...req.body,
    }
    await workspace.save()

    const user = await retrieveUser({ where: { email: req.user.email.full } })
    await setUserSession(req, user)

    res.json({ settings: workspace.settings })
  }
  catch (err) {
    next(err)
  }
})
