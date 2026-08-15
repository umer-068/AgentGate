# Package agentgate.authz is AgentGate's default policy bundle.
#
# Decision model:
#   1. Explicit deny rules (data.agentgate.deny_rules) always win, regardless
#      of what scope the agent's session token carries. This is the
#      "blast-radius ceiling" - e.g. production resources or raw shell
#      execution can be denied org-wide even if someone mis-scopes a token.
#   2. Otherwise, the call is allowed only if the agent's session token
#      carries a scope of the form "tool:<tool>:<action>" (or
#      "tool:<tool>:*") matching the requested tool call.
#   3. Everything else is denied by default.
package agentgate.authz

import future.keywords.in

default decision = {
	"allowed": false,
	"reason": "no matching allow rule",
	"policy_id": "default-deny",
}

decision = result {
	deny_reason := explicit_deny_reason
	result := {
		"allowed": false,
		"reason": deny_reason,
		"policy_id": "explicit-deny",
	}
}

decision = result {
	not explicit_deny_reason
	matched_scope := allowing_scope
	result := {
		"allowed": true,
		"reason": sprintf("scope '%s' grants %s on tool '%s'", [matched_scope, input.action, input.tool]),
		"policy_id": "scope-allow",
	}
}

explicit_deny_reason = reason {
	some rule in data.agentgate.deny_rules
	rule.tool == input.tool
	glob.match(rule.resource_pattern, [], input.resource)
	reason := rule.reason
}

allowing_scope = scope {
	some scope in input.scopes
	scope_matches(scope)
}

scope_matches(scope) {
	parts := split(scope, ":")
	count(parts) == 3
	parts[0] == "tool"
	parts[1] == input.tool
	action_matches(parts[2])
}

action_matches(action) {
	action == "*"
}

action_matches(action) {
	action == input.action
}
