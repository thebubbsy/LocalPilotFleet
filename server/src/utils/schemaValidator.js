/**
 * LocalPilot Fleet — JSON Schema Contract Validator
 * Validates REST API request payloads against defined schemas to prevent invalid data ingestion.
 */

export class SchemaValidator {
  static validate(schema, data) {
    if (!schema || typeof schema !== 'object') return { valid: true };
    if (!data || typeof data !== 'object') {
      return { valid: false, errors: ['Request body must be a non-null JSON object'] };
    }

    const errors = [];

    // Required fields check
    if (Array.isArray(schema.required)) {
      for (const field of schema.required) {
        if (data[field] === undefined || data[field] === null || data[field] === '') {
          errors.push(`Missing mandatory property: ${field}`);
        }
      }
    }

    // Property types & constraints
    if (schema.properties) {
      for (const [prop, rules] of Object.entries(schema.properties)) {
        const val = data[prop];
        if (val === undefined || val === null) continue;

        if (rules.type) {
          if (rules.type === 'string' && typeof val !== 'string') {
            errors.push(`Property '${prop}' must be a string (received ${typeof val})`);
          } else if (rules.type === 'integer' && (!Number.isInteger(val))) {
            errors.push(`Property '${prop}' must be an integer (received ${typeof val})`);
          } else if (rules.type === 'number' && typeof val !== 'number') {
            errors.push(`Property '${prop}' must be a number (received ${typeof val})`);
          } else if (rules.type === 'boolean' && typeof val !== 'boolean') {
            errors.push(`Property '${prop}' must be a boolean (received ${typeof val})`);
          } else if (rules.type === 'array' && !Array.isArray(val)) {
            errors.push(`Property '${prop}' must be an array (received ${typeof val})`);
          }
        }

        if (Array.isArray(rules.enum) && !rules.enum.includes(val)) {
          errors.push(`Property '${prop}' value '${val}' is not in allowed enum: [${rules.enum.join(', ')}]`);
        }

        if (rules.minLength && typeof val === 'string' && val.length < rules.minLength) {
          errors.push(`Property '${prop}' length must be at least ${rules.minLength}`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  static middleware(schema) {
    return (req, res, next) => {
      const result = SchemaValidator.validate(schema, req.body);
      if (!result.valid) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'SCHEMA_VALIDATION_ERROR',
          message: 'Request payload violated API schema contract',
          violations: result.errors
        }));
        return;
      }
      next();
    };
  }
}
