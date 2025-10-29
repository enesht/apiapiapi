/**
 * Lambda Handler for Akca API
 * Bu dosya Express app'i Lambda event'ine dönüştürür
 */

const serverlessHttp = require('serverless-http');

// Express app'i dynamically import et
let app;
let handler;

async function getHandler() {
  if (!handler) {
    // index.js'den express app'i al
    const indexModule = await import('./src/index.js');
    app = indexModule.app;
    handler = serverlessHttp(app);
  }
  return handler;
}

// Lambda handler
exports.handler = async (event, context) => {
  try {
    const h = await getHandler();
    return await h(event, context);
  } catch (error) {
    console.error('Lambda error:', error);
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify({
        ok: false,
        error: 'Internal server error',
        message: error.message
      }),
    };
  }
};
