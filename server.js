require('dotenv').config();

const { Verify2 } = require('@vonage/verify2');
const { Auth } = require('@vonage/auth');
const express = require('express');

const app = express();
app.use(express.json());

// --- Okta Inline Hook header auth (validate every request) ---
const AUTH_HEADER_KEY = process.env.AUTH_HEADER_KEY || 'Authorization';
const AUTH_HEADER_VALUE = process.env.AUTH_HEADER_VALUE;

app.get('/health', (req, res) => {
  console.log('[HEALTH]', new Date().toISOString());
  res.status(200).send('ok');
});

app.use((req, res, next) => {
  const incoming = req.headers[AUTH_HEADER_KEY.toLowerCase()];
  if (!AUTH_HEADER_VALUE || incoming !== AUTH_HEADER_VALUE) {
    return res.status(401).send('Unauthorized'); // reject non-Okta callers
  }
  next();
});

// --- Vonage Verify v2 client (JWT with Application ID + private key) ---
const credentials = new Auth({
  applicationId: process.env.VONAGE_APPLICATION_ID,
  privateKey: process.env.VONAGE_PRIVATE_KEY,
});

const brand = process.env.VERIFY_BRAND || 'Paramount';
const verifyClient = new Verify2(credentials, {});

// --- Track active verify request per phone so we can cancel before re-requesting ---
const activeVerifications = new Map(); // Map<string /* phone */, string /* request_id */>

// --- Inline Hook endpoint ---
app.post('/verify', async (req, res) => {
  try {
    const mp = req.body?.data?.messageProfile || {};
    // Keep E.164 WITH leading '+' for Verify v2
    const number = String(mp.phoneNumber);
    // Okta sends deliveryChannel like 'SMS' or 'VOICE'; Verify expects lowercase.
    const channel = String(mp.deliveryChannel || 'SMS');

    const ret = await sendVerificationRequest(number, channel);
    res.send(ret);
  } catch (e) {
    res.status(500).send(getErrorResponse('verify', e));
  }
});

// --- Start the server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));

// --- Helper: create Verify v2 request from Okta payload ---
async function sendVerificationRequest(number, channel) {
  const chl = channel.toLowerCase(); // 'sms' or 'voice'

  // 1) Cancel any tracked active request for this number to avoid 409 "Concurrent verifications"
  const priorId = activeVerifications.get(number);
  if (priorId) {
    try {
      // Node SDK cancel — standalone client uses verifyClient.cancel(requestId)
      await verifyClient.cancel(priorId);
      console.log('Canceled prior verify:', priorId);
    } catch (cancelErr) {
      console.log('Cancel failed (continuing):', cancelErr?.message || cancelErr);
    } finally {
      activeVerifications.delete(number);
    }
  }

  // 2) Build Verify v2 request body: brand + workflow (no custom 'code' unless your pricing supports it)
  const params = {
    brand,                        // required by Verify v2
    workflow: [{ channel: chl, to: number }],  // channel + destination in E.164
    // NOTE: Do NOT set 'code' unless you're on Verify Conversion. Let Vonage generate the OTP.  [1](https://developer.vonage.com/en/api/verify.v2)
  };

  try {
    // Official Node SDK call to start a verification (v2)
    // In @vonage/verify2 the create call is `newRequest(...)`
    const resp = await verifyClient.newRequest(params);
    console.log(resp);
    // 3) Record request_id so we can cancel next time if needed
    const reqId = resp?.requestId || resp?.request_id || resp?.data?.request_id;
    if (reqId) activeVerifications.set(number, reqId);
    return getSuccessResponse('verify', reqId);
  } catch (error) {
    console.error(error?.response ?? error);
    // Bubble to caller so the hook returns a safe error structure
    throw error;
  }
}

// --- Okta telephony inline-hook success response ---
function getSuccessResponse(method, sid) {
  console.log(`Successfully sent ${method} : ${sid}`);
  const actionKey = 'com.okta.telephony.action';
  const actionVal = 'SUCCESSFUL';
  const providerName = 'VONAGE';
  return {
    commands: [
      {
        type: actionKey,
        value: [
          {
            status: actionVal,
            provider: providerName,
            transactionId: sid,
          },
        ],
      },
    ],
  };
}

// --- Okta telephony inline-hook error response (safe) ---
function getErrorResponse(method, error) {
  console.log(`Error in ${method} : ${error?.message || error}`);
  const title = error?.response?.data?.title || 'VerifyError';
  const detail = error?.response?.data?.detail || error?.message || 'Unknown error';
  const code = error?.code || 'VERIFY_ERROR';
  return {
    error: {
      errorSummary: title,
      errorCauses: [
        {
          errorSummary: code,
          reason: detail,
        },
      ],
    },
  };
}