// Same policy as afd-policy-portal.json, as Bicep.
param policyName string = 'wafexampledev'

resource wafPolicy 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2024-02-01' = {
  name: 'wafexampledev'
  location: 'Global'
  sku: {
    name: 'Premium_AzureFrontDoor'
  }
  properties: {
    policySettings: {
      enabledState: 'Enabled'
      mode: 'Prevention'
      requestBodyCheck: 'Enabled'
      customBlockResponseStatusCode: 403
    }
    customRules: {
      rules: [
        {
          name: 'AllowHealthProbe'
          enabledState: 'Enabled'
          priority: 10
          ruleType: 'MatchRule'
          action: 'Allow'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'BeginsWith'
              negateCondition: false
              matchValue: [
                '/healthz'
              ]
              transforms: [
                'Lowercase'
              ]
            }
          ]
        }
        {
          name: 'BlockGeo'
          enabledState: 'Enabled'
          priority: 20
          ruleType: 'MatchRule'
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'SocketAddr'
              operator: 'GeoMatch'
              matchValue: [
                'KP'
                'IR'
              ]
            }
          ]
        }
        {
          name: 'BlockAdminFromOutside'
          enabledState: 'Enabled'
          priority: 30
          ruleType: 'MatchRule'
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              matchValue: [ '/admin' ]
              transforms: [ 'Lowercase' ]
            }
            {
              matchVariable: 'RemoteAddr'
              operator: 'IPMatch'
              negateCondition: true
              matchValue: [ '10.0.0.0/8', '203.0.113.0/24' ]
            }
          ]
        }
        {
          name: 'LogLargeBodies'
          enabledState: 'Enabled'
          priority: 40
          ruleType: 'MatchRule'
          action: 'Log'
          matchConditions: [
            {
              matchVariable: 'RequestBody'
              operator: 'GreaterThan'
              matchValue: [ '100000' ]
            }
          ]
        }
        {
          name: 'RateLimitLogin'
          enabledState: 'Enabled'
          priority: 50
          ruleType: 'RateLimitRule'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: 100
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              matchValue: [ '/auth/' ]
              transforms: [ 'Lowercase' ]
            }
          ]
        }
        {
          name: 'OldDisabledRule'
          enabledState: 'Disabled'
          priority: 60
          ruleType: 'MatchRule'
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestMethod'
              operator: 'Equal'
              matchValue: [ 'PUT' ]
            }
          ]
        }
      ]
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'Microsoft_DefaultRuleSet'
          ruleSetVersion: '2.1'
          ruleSetAction: 'Block'
          exclusions: [
            {
              matchVariable: 'RequestCookieNames'
              selectorMatchOperator: 'Equals'
              selector: 'app_session'
            }
          ]
          ruleGroupOverrides: [
            {
              ruleGroupName: 'SQLI'
              rules: [
                {
                  ruleId: '942100'
                  enabledState: 'Enabled'
                  action: 'AnomalyScoring'
                  exclusions: [
                    {
                      matchVariable: 'RequestBodyJsonArgNames'
                      selectorMatchOperator: 'Equals'
                      selector: 'content'
                    }
                  ]
                }
                {
                  ruleId: '942200'
                  enabledState: 'Disabled'
                  action: 'AnomalyScoring'
                }
              ]
            }
            {
              ruleGroupName: 'METHOD-ENFORCEMENT'
              rules: [
                {
                  ruleId: '911100'
                  enabledState: 'Enabled'
                  action: 'AnomalyScoring'
                }
              ]
            }
          ]
        }
        {
          ruleSetType: 'Microsoft_BotManagerRuleSet'
          ruleSetVersion: '1.1'
        }
      ]
    }
  }
}
