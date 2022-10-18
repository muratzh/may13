import _ from 'lodash'
import { getStoreCredentials, apiDecorator } from '../utils'

export const LOAD_ALERTS_REQUEST = 'LOAD_ALERTS_REQUEST'
export const LOAD_ALERTS_SUCCESS = 'LOAD_ALERTS_SUCCESS'
export const LOAD_ALERTS_FAILURE = 'LOAD_ALERTS_FAILURE'

export const loadAlerts = projectId => (dispatch, getState) => {
  const { isFetching } = getState().alerts.loadStatus
  const { org, accessKey } = getStoreCredentials(getState())

  if (isFetching) {
    return Promise.resolve()
  }

  dispatch({ type: LOAD_ALERTS_REQUEST })
  return apiDecorator(
    `/list_alerts/${org}/${projectId}`,
    'POST',
    accessKey,
    'data_service',
    { alert_framework: 'pre-computed' }
  )
    .then(res => dispatch({ type: LOAD_ALERTS_SUCCESS, payload: res.result }))
    .catch(error => dispatch({ type: LOAD_ALERTS_FAILURE, error }))
}

export const DELETE_ALERT_REQUEST = 'DELETE_ALERT_REQUEST'
export const DELETE_ALERT_SUCCESS = 'DELETE_ALERT_SUCCESS'
export const DELETE_ALERT_FAILURE = 'DELETE_ALERT_FAILURE'

export const deleteAlert = (projectId, alertId) => (dispatch, getState) => {
  const { isFetching } = getState().alerts.deleteStatus
  const { org, accessKey } = getStoreCredentials(getState())

  if (isFetching) {
    return Promise.resolve()
  }

  dispatch({ type: DELETE_ALERT_REQUEST })

  return apiDecorator(
    `/delete_alert/${org}/${projectId}`,
    'POST',
    accessKey,
    'data_service',
    { alert_id: alertId, alert_framework: 'pre-computed' }
  )
    .then(res => dispatch({ type: DELETE_ALERT_SUCCESS, payload: alertId }))
    .catch(error => dispatch({ type: DELETE_ALERT_FAILURE, error }))
}
