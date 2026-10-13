# Same policy as afd-policy-portal.json, as Terraform (azurerm provider).
resource "azurerm_cdn_frontdoor_firewall_policy" "waf" {
  name                              = "wafexampledev"
  resource_group_name               = var.resource_group_name
  sku_name                          = "Premium_AzureFrontDoor"
  enabled                           = true
  mode                              = "Prevention"
  request_body_check_enabled        = true
  custom_block_response_status_code = 403

  custom_rule {
    name     = "AllowHealthProbe"
    enabled  = true
    priority = 10
    type     = "MatchRule"
    action   = "Allow"
    match_condition {
      match_variable = "RequestUri"
      operator       = "BeginsWith"
      match_values   = ["/healthz"]
      transforms     = ["Lowercase"]
    }
  }

  custom_rule {
    name     = "BlockGeo"
    enabled  = true
    priority = 20
    type     = "MatchRule"
    action   = "Block"
    match_condition {
      match_variable = "SocketAddr"
      operator       = "GeoMatch"
      match_values   = ["KP", "IR"]
    }
  }

  custom_rule {
    name     = "BlockAdminFromOutside"
    enabled  = true
    priority = 30
    type     = "MatchRule"
    action   = "Block"
    match_condition {
      match_variable = "RequestUri"
      operator       = "Contains"
      match_values   = ["/admin"]
      transforms     = ["Lowercase"]
    }
    match_condition {
      match_variable     = "RemoteAddr"
      operator           = "IPMatch"
      negation_condition = true
      match_values       = ["10.0.0.0/8", "203.0.113.0/24"]
    }
  }

  custom_rule {
    name     = "LogLargeBodies"
    enabled  = true
    priority = 40
    type     = "MatchRule"
    action   = "Log"
    match_condition {
      match_variable = "RequestBody"
      operator       = "GreaterThan"
      match_values   = ["100000"]
    }
  }

  custom_rule {
    name                           = "RateLimitLogin"
    enabled                        = true
    priority                       = 50
    type                           = "RateLimitRule"
    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = 100
    action                         = "Block"
    match_condition {
      match_variable = "RequestUri"
      operator       = "Contains"
      match_values   = ["/auth/"]
      transforms     = ["Lowercase"]
    }
  }

  custom_rule {
    name     = "OldDisabledRule"
    enabled  = false
    priority = 60
    type     = "MatchRule"
    action   = "Block"
    match_condition {
      match_variable = "RequestMethod"
      operator       = "Equal"
      match_values   = ["PUT"]
    }
  }

  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"

    exclusion {
      match_variable = "RequestCookieNames"
      operator       = "Equals"
      selector       = "app_session"
    }

    override {
      rule_group_name = "SQLI"
      rule {
        rule_id = "942100"
        enabled = true
        action  = "AnomalyScoring"
        exclusion {
          match_variable = "RequestBodyJsonArgNames"
          operator       = "Equals"
          selector       = "content"
        }
      }
      rule {
        rule_id = "942200"
        enabled = false
        action  = "AnomalyScoring"
      }
    }

    override {
      rule_group_name = "METHOD-ENFORCEMENT"
      rule {
        rule_id = "911100"
        enabled = true
        action  = "AnomalyScoring"
      }
    }
  }

  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = "1.1"
    action  = "Block"
  }
}
