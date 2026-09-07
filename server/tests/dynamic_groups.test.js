/**
 * LocalPilot Fleet — Dynamic Group AST & Evaluator Truth Table Tests
 * server/tests/dynamic_groups.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateRule, parseRule } from '../src/services/dynamicGroups.js';

describe('Dynamic Group AST & Evaluator Truth Table (dynamic_groups.test.js)', () => {
  const sampleDevice = {
    Hostname: 'GAMING-RIG-01',
    FriendlyName: "Dad's Workstation",
    TotalRAM_GB: 32.0,
    OSVersion: '10.0.22631.3296',
    OSName: 'Microsoft Windows 11 Pro',
    GPU: 'NVIDIA GeForce RTX 4090',
    HasBattery: false,
    BatteryPercent: null,
    TPMEnabled: true,
    SecureBoot: true,
    BitLocker: 'FullyEncrypted',
    Group: 'Workstations',
    Tags: ['gaming', 'family', 'homelab', 'vr'],
    Route: 'LAN',
    Status: 'online'
  };

  describe('1. Equality Operators (-eq, -ne)', () => {
    it('evaluates string equality case-insensitively', () => {
      assert.equal(evaluateRule("Device.Hostname -eq 'gaming-rig-01'", sampleDevice), true);
      assert.equal(evaluateRule("Device.Hostname -eq 'GAMING-RIG-01'", sampleDevice), true);
      assert.equal(evaluateRule("Device.Hostname -eq 'OTHER-PC'", sampleDevice), false);
      assert.equal(evaluateRule("Device.Hostname -ne 'OTHER-PC'", sampleDevice), true);
      assert.equal(evaluateRule("Device.Hostname -ne 'gaming-rig-01'", sampleDevice), false);
    });

    it('evaluates numeric equality with type coercion', () => {
      assert.equal(evaluateRule("Device.TotalRAM_GB -eq 32", sampleDevice), true);
      assert.equal(evaluateRule("Device.TotalRAM_GB -eq 32.0", sampleDevice), true);
      assert.equal(evaluateRule("Device.TotalRAM_GB -eq '32'", sampleDevice), true);
      assert.equal(evaluateRule("Device.TotalRAM_GB -eq 64", sampleDevice), false);
      assert.equal(evaluateRule("Device.TotalRAM_GB -ne 64", sampleDevice), true);
    });

    it('evaluates boolean equality with PowerShell literals ($true, $false)', () => {
      assert.equal(evaluateRule("Device.HasBattery -eq false", sampleDevice), true);
      assert.equal(evaluateRule("Device.HasBattery -eq $false", sampleDevice), true);
      assert.equal(evaluateRule("Device.HasBattery -eq true", sampleDevice), false);
      assert.equal(evaluateRule("Device.TPMEnabled -eq true", sampleDevice), true);
      assert.equal(evaluateRule("Device.TPMEnabled -eq $true", sampleDevice), true);
      assert.equal(evaluateRule("Device.TPMEnabled -ne false", sampleDevice), true);
    });
  });

  describe('2. Relational Comparison Operators (-gt, -ge, -lt, -le)', () => {
    it('evaluates greater-than and greater-or-equal', () => {
      assert.equal(evaluateRule("Device.TotalRAM_GB -gt 16", sampleDevice), true);
      assert.equal(evaluateRule("Device.TotalRAM_GB -gt 32", sampleDevice), false);
      assert.equal(evaluateRule("Device.TotalRAM_GB -ge 32", sampleDevice), true);
      assert.equal(evaluateRule("Device.TotalRAM_GB -ge 64", sampleDevice), false);
    });

    it('evaluates less-than and less-or-equal', () => {
      assert.equal(evaluateRule("Device.TotalRAM_GB -lt 64", sampleDevice), true);
      assert.equal(evaluateRule("Device.TotalRAM_GB -lt 32", sampleDevice), false);
      assert.equal(evaluateRule("Device.TotalRAM_GB -le 32", sampleDevice), true);
      assert.equal(evaluateRule("Device.TotalRAM_GB -le 16", sampleDevice), false);
    });

    it('handles floating point comparisons accurately', () => {
      assert.equal(evaluateRule("Device.TotalRAM_GB -gt 31.99", sampleDevice), true);
      assert.equal(evaluateRule("Device.TotalRAM_GB -lt 32.01", sampleDevice), true);
    });
  });

  describe('3. Wildcard Matching Operators (-like, -notlike)', () => {
    it('matches wildcard prefixes (10.0.22*)', () => {
      assert.equal(evaluateRule("Device.OSVersion -like '10.0.22*'", sampleDevice), true);
      assert.equal(evaluateRule("Device.OSVersion -like '10.0.19*'", sampleDevice), false);
      assert.equal(evaluateRule("Device.OSVersion -notlike '10.0.19*'", sampleDevice), true);
    });

    it('matches wildcard substrings (*NVIDIA*) case-insensitively', () => {
      assert.equal(evaluateRule("Device.GPU -like '*NVIDIA*'", sampleDevice), true);
      assert.equal(evaluateRule("Device.GPU -like '*nvidia*'", sampleDevice), true);
      assert.equal(evaluateRule("Device.GPU -like '*RTX 4090*'", sampleDevice), true);
      assert.equal(evaluateRule("Device.GPU -like '*Radeon*'", sampleDevice), false);
      assert.equal(evaluateRule("Device.GPU -notlike '*Radeon*'", sampleDevice), true);
    });

    it('matches universal catch-all (*)', () => {
      assert.equal(evaluateRule("Device.Hostname -like '*'", sampleDevice), true);
    });

    it('matches single character wildcard (?)', () => {
      assert.equal(evaluateRule("Device.Hostname -like 'GAMING-RIG-??'", sampleDevice), true);
      assert.equal(evaluateRule("Device.Hostname -like 'GAMING-RIG-?'", sampleDevice), false);
    });
  });

  describe('4. Collection Membership Operators (-contains, -notcontains)', () => {
    it('evaluates whether array property contains a scalar element', () => {
      assert.equal(evaluateRule("Device.Tags -contains 'homelab'", sampleDevice), true);
      assert.equal(evaluateRule("Device.Tags -contains 'HOMELAB'", sampleDevice), true); // case-insensitive
      assert.equal(evaluateRule("Device.Tags -contains 'work'", sampleDevice), false);
      assert.equal(evaluateRule("Device.Tags -notcontains 'work'", sampleDevice), true);
      assert.equal(evaluateRule("Device.Tags -notcontains 'gaming'", sampleDevice), false);
    });
  });

  describe('5. Set Inclusion Operators (-in, -notin)', () => {
    it('evaluates whether scalar property exists in literal array', () => {
      assert.equal(evaluateRule("Device.Group -in ['Workstations', 'Servers']", sampleDevice), true);
      assert.equal(evaluateRule("Device.Group -in ['workstations']", sampleDevice), true); // case-insensitive
      assert.equal(evaluateRule("Device.Group -in ['Family', 'Laptops']", sampleDevice), false);
      assert.equal(evaluateRule("Device.Group -notin ['Family', 'Laptops']", sampleDevice), true);
      assert.equal(evaluateRule("Device.Group -notin ['Workstations']", sampleDevice), false);
    });
  });

  describe('6. Null & Missing Property Resilience', () => {
    it('safely returns false without throwing when comparing null/missing property', () => {
      // BatteryPercent is null on desktop
      assert.equal(evaluateRule("Device.BatteryPercent -lt 20", sampleDevice), false);
      assert.equal(evaluateRule("Device.BatteryPercent -gt 50", sampleDevice), false);
      assert.equal(evaluateRule("Device.NonExistentField -eq 'test'", sampleDevice), false);
      assert.equal(evaluateRule("Device.NonExistentField -like '*'", sampleDevice), false);
    });
  });

  describe('7. Compound Logical Expressions (and, or, not, parentheses)', () => {
    it('evaluates and / -and expressions', () => {
      assert.equal(evaluateRule("Device.TotalRAM_GB -ge 32 and Device.GPU -like '*NVIDIA*'", sampleDevice), true);
      assert.equal(evaluateRule("Device.TotalRAM_GB -ge 32 -and Device.GPU -like '*AMD*'", sampleDevice), false);
    });

    it('evaluates or / -or expressions', () => {
      assert.equal(evaluateRule("Device.HasBattery -eq true or Device.TotalRAM_GB -ge 32", sampleDevice), true);
      assert.equal(evaluateRule("Device.HasBattery -eq true -or Device.GPU -like '*AMD*'", sampleDevice), false);
    });

    it('evaluates not / -not expressions', () => {
      assert.equal(evaluateRule("not (Device.HasBattery -eq true)", sampleDevice), true);
      assert.equal(evaluateRule("-not (Device.TotalRAM_GB -lt 16)", sampleDevice), true);
    });

    it('respects parentheses precedence over default operator precedence', () => {
      // (false or true) and true -> true
      assert.equal(
        evaluateRule("(Device.HasBattery -eq true or Device.TPMEnabled -eq true) and Device.SecureBoot -eq true", sampleDevice),
        true
      );

      // false and (true or true) -> false
      assert.equal(
        evaluateRule("Device.HasBattery -eq true and (Device.TPMEnabled -eq true or Device.SecureBoot -eq true)", sampleDevice),
        false
      );
    });

    it('evaluates the official project Workstation rule', () => {
      const rule = "Device.TotalRAM_GB -ge 32 and Device.GPU -like '*NVIDIA*' and Device.HasBattery -eq false";
      assert.equal(evaluateRule(rule, sampleDevice), true);
    });
  });

  describe('8. Syntax Error Handling & Validation', () => {
    it('returns valid: false or throws clear parse error on unclosed parentheses', () => {
      const result = parseRule("(Device.TotalRAM_GB -ge 32");
      assert.equal(result.valid, false);
      assert.ok(result.error);
    });

    it('returns valid: false on missing operator', () => {
      const result = parseRule("Device.TotalRAM_GB 32");
      assert.equal(result.valid, false);
    });

    it('returns valid: false on unsupported operator', () => {
      const result = parseRule("Device.TotalRAM_GB -magic 32");
      assert.equal(result.valid, false);
    });

    it('handles empty string gracefully', () => {
      const result = parseRule("");
      assert.equal(result.valid, false);
      assert.equal(evaluateRule("", sampleDevice), false);
    });
  });
});
