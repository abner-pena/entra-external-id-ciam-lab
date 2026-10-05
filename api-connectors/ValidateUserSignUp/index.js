// API connector (Azure Function, HTTP trigger) called by Entra External ID
// at the "before creating the user" step of the self-service sign-up flow.
//
// Responsibilities:
//   1. Reject sign-up if the email domain is a known disposable-email provider.
//   2. Reject sign-up if the email matches the internal denylist (abuse reports, prior bans).
//   3. Compute a riskTier claim from available signal and return it so the relying
//      app and Conditional Access can both evaluate it downstream.
//
// Entra External ID expects a specific response contract: either a 200 with the
// claims to attach to the token, or a 400 with a validation error the sign-up
// page renders directly to the user.

const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com",
  "10minutemail.com",
  "guerrillamail.com",
  "tempmail.com",
  "yopmail.com",
  "trashmail.com"
]);

// In production this reads from a managed denylist store (Table Storage, Cosmos DB).
// Kept as a static set here to keep the lab self-contained.
const DENYLIST_EMAILS = new Set([
  "known-abuser@example.com"
]);

function extractDomain(email) {
  const at = email.lastIndexOf("@");
  if (at === -1) return "";
  return email.slice(at + 1).toLowerCase();
}

function computeRiskTier({ domain, isDisposable, ipReputationFlag }) {
  if (isDisposable || ipReputationFlag) return "high";
  const freeConsumerDomains = new Set(["gmail.com", "outlook.com", "yahoo.com", "hotmail.com"]);
  if (freeConsumerDomains.has(domain)) return "medium";
  return "low";
}

module.exports = async function (context, req) {
  const body = req.body || {};
  const email = (body.email || "").toLowerCase().trim();

  context.log(`ValidateUserSignUp invoked for correlationId=${body.correlationId || "unknown"}`);

  if (!email || !email.includes("@")) {
    context.res = {
      status: 400,
      body: {
        version: "1.0.0",
        status: 400,
        userMessage: "Enter a valid email address to continue."
      }
    };
    return;
  }

  const domain = extractDomain(email);
  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  const isDenylisted = DENYLIST_EMAILS.has(email);

  if (isDisposable) {
    context.log.warn(`Blocked signup: disposable domain (${domain})`);
    context.res = {
      status: 400,
      body: {
        version: "1.0.0",
        status: 400,
        userMessage: "Please sign up with a permanent email address. Temporary or disposable email providers are not supported."
      }
    };
    return;
  }

  if (isDenylisted) {
    context.log.warn(`Blocked signup: denylisted email`);
    context.res = {
      status: 400,
      body: {
        version: "1.0.0",
        status: 400,
        userMessage: "We were unable to complete your sign-up. Contact support if you believe this is an error."
      }
    };
    return;
  }

  // ipReputationFlag would come from an upstream reputation check (Azure Web
  // Application Firewall custom rule output, or a third-party IP reputation API)
  // passed through in the request body by the sign-up flow. Defaulted to false here.
  const ipReputationFlag = Boolean(body.ipReputationFlag);
  const riskTier = computeRiskTier({ domain, isDisposable, ipReputationFlag });

  context.res = {
    status: 200,
    body: {
      version: "1.0.0",
      action: "Continue",
      extension_riskTier: riskTier
    }
  };
};
