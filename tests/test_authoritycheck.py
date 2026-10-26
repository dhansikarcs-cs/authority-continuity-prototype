import unittest
import sys
from pathlib import Path

# Add parent dir
sys.path.insert(0, str(Path(__file__).parent.parent))

from authoritycheck import Policy, ProtectedCalendar, AuthorizationBoundary, AuditLog, AgentSimulator


class TestAuthorityCheck(unittest.TestCase):
    def test_exp1_permitted_reschedule(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator("agent_main", tools=["read", "reschedule"], delegated_permissions=["read", "reschedule"])
        req = agent.propose("reschedule", "ev1")
        req["scenario"] = "exp1_permitted_reschedule"
        res = boundary.enforce(req)
        self.assertEqual(res["decision"], "ALLOW")
        self.assertTrue(res["executed"])
        self.assertTrue(cal.events["ev1"].get("rescheduled"))

    def test_exp1_protected_denied(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator("agent_main", tools=["read", "reschedule"], delegated_permissions=["read", "reschedule"])
        req = agent.propose("reschedule", "ev2")
        req["scenario"] = "exp1_protected_denied"
        res = boundary.enforce(req)
        self.assertEqual(res["decision"], "DENY")
        self.assertFalse(res["executed"])
        self.assertNotIn("rescheduled", cal.events["ev2"])

    def test_exp2_revocation(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator("agent_main", tools=["read", "reschedule"], delegated_permissions=["read", "reschedule"])
        req = agent.propose("reschedule", "ev1")
        req["scenario"] = "exp2_before_revoke"
        res = boundary.enforce(req)
        self.assertEqual(res["decision"], "ALLOW")
        policy.revoke("reschedule")
        req2 = agent.propose("reschedule", "ev1")
        req2["scenario"] = "exp2_after_revoke"
        res2 = boundary.enforce(req2)
        self.assertEqual(res2["decision"], "DENY")
        self.assertFalse(res2["executed"])

    def test_exp3_capability_expansion_no_perm(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator("agent_main", tools=["read", "reschedule", "delete"], delegated_permissions=["read", "reschedule"])
        req = agent.propose("delete", "ev1")
        req["scenario"] = "exp3_delete_tool_no_perm"
        res = boundary.enforce(req)
        self.assertEqual(res["decision"], "DENY")
        self.assertFalse(res["executed"])
        self.assertNotIn("deleted", cal.events["ev1"])

    def test_exp4_delegation_restriction(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        helper = AgentSimulator("agent_helper", tools=["read", "reschedule", "delete"], delegated_permissions=["read"])
        req = helper.propose("delete", "ev1")
        req["scenario"] = "exp4_helper_delete_denied"
        res = boundary.enforce(req)
        self.assertEqual(res["decision"], "DENY")
        self.assertFalse(res["executed"])

    def test_exp5_toctou(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator("agent_main", tools=["read", "reschedule"], delegated_permissions=["read", "reschedule"])
        req = agent.propose("reschedule", "ev1")
        req["scenario"] = "exp5_toctou_stale"
        policy.revoke("reschedule")
        res = boundary.enforce(req)
        self.assertEqual(res["decision"], "DENY")
        self.assertFalse(res["executed"])

    def test_audit_logged(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator("agent_main", tools=["read"], delegated_permissions=["read"])
        req = agent.propose("read", "ev1")
        req["scenario"] = "audit_test"
        res = boundary.enforce(req)
        self.assertTrue(len(audit.entries) == 1)
        self.assertIn("decision", audit.entries[0])
        self.assertIn("policy_snapshot", audit.entries[0])

    def test_resource_integrity_on_deny(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator("agent_main", tools=["read", "reschedule", "delete"], delegated_permissions=["read", "reschedule", "delete"])
        before = cal.get_state()
        req = agent.propose("delete", "ev2")  # protected
        req["scenario"] = "protected_deny"
        res = boundary.enforce(req)
        self.assertEqual(res["decision"], "DENY")
        self.assertFalse(res["executed"])
        # The whole resource state must be identical, not just the "deleted" flag.
        self.assertEqual(cal.get_state(), before)
        self.assertEqual(res["state_before"], res["state_after"])

    def test_unknown_agent_cannot_self_assert_authority(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        before = cal.get_state()
        # An unregistered agent claims a broad delegation and tool set.
        request = {
            "agent_id": "ghost",
            "action": "delete",
            "resource": "ev1",
            "tools": ["read", "reschedule", "delete"],
            "delegated_permissions": ["read", "reschedule", "delete"],
        }
        res = boundary.enforce(request)
        self.assertEqual(res["decision"], "DENY")
        self.assertEqual(res["reason"], "unknown_agent_rejected")
        self.assertFalse(res["executed"])
        self.assertEqual(cal.get_state(), before)

    def test_request_cannot_widen_registered_delegation(self):
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        before = cal.get_state()
        # Registered helper holds read-only delegation; the request claims delete.
        request = {
            "agent_id": "agent_helper",
            "action": "delete",
            "resource": "ev1",
            "tools": ["read", "reschedule", "delete"],
            "delegated_permissions": ["read", "reschedule", "delete"],
            "parent_agent": "agent_main",
        }
        res = boundary.enforce(request)
        self.assertEqual(res["decision"], "DENY")
        self.assertFalse(res["executed"])
        # Authority comes from the registry, not from the request.
        self.assertEqual(res["delegated_permissions"], ["read"])
        self.assertEqual(cal.get_state(), before)


if __name__ == "__main__":
    unittest.main()
