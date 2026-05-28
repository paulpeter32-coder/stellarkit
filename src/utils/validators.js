const { StrKey } = require("@stellar/stellar-sdk");

/**
 * Validate a Stellar account ID.
 *
 * @param {string} accountId - The Stellar account ID to validate.
 * @throws {Error} If the account ID is missing or invalid.
 */
function validateAccountId(accountId) {
  if (!accountId) {
    const err = new Error("Account ID is required.");
    err.isValidation = true;
    throw err;
  }
  if (!StrKey.isValidEd25519PublicKey(accountId)) {
    const err = new Error(
      `Invalid Stellar account ID: "${accountId}". Must be a valid Ed25519 public key starting with "G".`,
    );
    err.isValidation = true;
    throw err;
  }
}

/**
 * Validate an asset code.
 *
 * @param {string} code - The asset code to validate.
 * @throws {Error} If the asset code is missing or invalid.
 */
function validateAssetCode(code) {
  if (!code) {
    const err = new Error("Asset code is required.");
    err.isValidation = true;
    throw err;
  }
  if (!/^[A-Z0-9]{1,12}$/.test(code.toUpperCase())) {
    const err = new Error(
      `Invalid asset code: "${code}". Must be 1–12 uppercase alphanumeric characters.`,
    );
    err.isValidation = true;
    throw err;
  }
}

/**
 * Validate a numeric limit and return it as an integer.
 *
 * @param {number|string} limit - The limit value to validate.
 * @param {number} [max=200] - The maximum allowed limit.
 * @returns {number} The parsed limit value.
 * @throws {Error} If the limit is not a number or is out of range.
 */
function validateLimit(limit, max = 200) {
  const parsed = parseInt(limit);
  if (isNaN(parsed) || parsed < 1 || parsed > max) {
    const err = new Error(`Limit must be a number between 1 and ${max}.`);
    err.isValidation = true;
    throw err;
  }
  return parsed;
}

/**
 * Inspect a raw string and return a human-readable reason why it is not a
 * valid Stellar Ed25519 public key, or null when it looks valid.
 *
 * The checks are ordered from most-obvious to least-obvious so the returned
 * message is as helpful as possible.
 *
 * @param {string} id - The raw input to inspect.
 * @returns {string|null} A reason string, or null when the key is valid.
 */
function publicKeyInvalidReason(id) {
  if (!id || id.trim() === "") return "Input is empty.";

  // Stellar public keys are base32-encoded and always start with "G"
  if (!id.startsWith("G")) {
    return `Wrong prefix: Stellar public keys must start with "G", got "${id[0]}".`;
  }

  // A valid Ed25519 public key encodes 32 bytes + a 2-byte checksum in
  // base32, which always produces exactly 56 characters.
  if (id.length !== 56) {
    return `Wrong length: expected 56 characters, got ${id.length}.`;
  }

  // Base32 alphabet is A-Z and 2-7 (RFC 4648).
  if (/[^A-Z2-7]/.test(id)) {
    return "Invalid characters: Stellar public keys may only contain A-Z and 2-7.";
  }

  // Let the SDK do the final checksum / structural validation.
  if (!StrKey.isValidEd25519PublicKey(id)) {
    return "Invalid key: checksum or structure does not match a valid Ed25519 public key.";
  }

  return null;
}

module.exports = { validateAccountId, validateAssetCode, validateLimit, publicKeyInvalidReason };
