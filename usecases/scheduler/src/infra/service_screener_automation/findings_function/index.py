def lambda_handler(event, context):
  message = 'Hello World!'
  return {
    'message': event
  }