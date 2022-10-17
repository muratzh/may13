import http from 'http'
import https from 'https'
import express from 'express'
import helmet from 'helmet'
import compress from 'compression'
import morgan from 'morgan'
import cors from 'cors'
import proxy from 'http-proxy-middleware'

import sso from './api/sso/handler'
import config from './config'
import api from './api/router'
import session from './api/session'
import servicesProxy from './proxy/servicesProxy'
import {proxyMiddleware} from './proxy/authorizationMiddleware'
import { errorHandler } from './api/utils'


const app = express()
const server = http.createServer(app)

// Prevent clickjacking via HTML iframes
// See: https://owasp.org/www-community/attacks/Clickjacking
// Helmet's content security policy options are defined here: https://helmetjs.github.io/#reference
app.use(helmet.contentSecurityPolicy({
  useDefaults: false,
  directives: {
    // default-src must be defined to prevent the error “Content-Security-Policy needs a default-src but none was provided”
    'default-src': helmet.contentSecurityPolicy.dangerouslyDisableDefaultSrc,
    'frame-ancestors': ["'self'"],
  },
}));
app.use(helmet.frameguard());

app.disable('x-powered-by')
app.set('trust proxy', true)

// health check (for ELB)
app.get('/health', (req, res) => res.send('ok'))

// place middleware above logger to prevent request logging
app.use(morgan(config.logFormat || 'short'))

app.use(session)

// Passport
app.use(sso.passport.initialize())

app.use(sso.passport.session())

sso.passport.serializeUser(function (user, done) {
  done(null, user)
})

sso.passport.deserializeUser(function (user, done) {
  done(null, user)
})

// API routes
app.use('/api', compress(), cors(config.cors), api)

// ---- We get the envoy running in onebox then none of the urls for other services should come to admin service. so if we don't have a route and are hitting admin service it should throw 404
// proxy middleware
// app.use(proxyMiddleware)


// services proxy
// app.use(servicesProxy(server), errorHandler)
// ---

// @todo: The UI should not be proxied through admin service but directly served
// ----------------------------------------

// serve webapp from CDN
if (config.useCDN) {
  app.use(
    proxy({
      target: config.useCDN,
      pathRewrite: () => '/index.html',
    })
  )
}

// serve webapp from file system
if (config.usePublicFolder) {
  app.use([
    // serve static assets
    express.static(config.usePublicFolder),
    // catch-all fallback - serve react app index.html
    (req, res) => {
      res.sendFile('index.html', { root: config.usePublicFolder })
    },
  ])
  app.use('/docs', express.static(__dirname + '/docs'))
}
// ----------------------------------------

server.listen(config.port, () => {
  console.log(`Server listening on port ${config.port}`)
})

// HTTPS support
if (config.secure) {
  const secureServer = https.createServer(config.secureOptions(), app)
  secureServer.listen(config.securePort, () => {
    console.log(`Secure server listening on port ${config.securePort}`)
  })
}
