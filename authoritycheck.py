#!/usr/bin/env python3
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent if '__file__' in globals() else Path('.')
REPORTS_DIR = BASE_DIR / 'reports'


class ProtectedCalendar:
    def __init__(self):
        self.events = {
            'ev1': {'id': 'ev1', 'title': 'Team Meeting', 'protected': False},
            'ev2': {'id': 'ev2', 'title': 'Confidential Board Review', 'protected': True},
        }

    def get_state(self):
        return {k: dict(v) for k, v in self.events.items()}

    def read(self, event_id):
        if event_id not in self.events:
            raise KeyError('event not found')
        return dict(self.events[event_id])

    def reschedule(self, event_id):
        if event_id not in self.events:
            raise KeyError('event not found')
        ev = self.events[event_id]
        if ev.get('protected'):
            raise PermissionError('protected event')
        ev['rescheduled'] = True
        return dict(ev)

    def delete(self, event_id):
        if event_id not in self.events:
            raise KeyError('event not found')
        ev = self.events[event_id]
        if ev.get('protected'):
            raise PermissionError('protected event')
        ev['deleted'] = True
        return dict(ev)


class Policy:
    def __init__(self):
        self.permitted_actions = {'read', 'reschedule'}
        self.prohibited_actions = set()
        self.protected_resources = {'ev2'}
        self.requires_approval = {'delete'}
        self.revoked = set()
        self.version = 1

    def revoke(self, action):
        self.revoked.add(action)
        self.version += 1

    def grant(self, action):
        if action in self.revoked:
            self.revoked.discard(action)
        if action not in self.permitted_actions:
            self.permitted_actions.add(action)
        self.version += 1

    def snapshot(self):
        return {
            'permitted_actions': sorted(list(self.permitted_actions)),
            'revoked': sorted(list(self.revoked)),
            'protected_resources': sorted(list(self.protected_resources)),
            'requires_approval': sorted(list(self.requires_approval)),
            'version': self.version,
        }


class AuditLog:
    def __init__(self):
        self.entries = []

    def log(self, entry):
        self.entries.append(entry)


class AgentSimulator:
    def __init__(self, agent_id, tools=None, delegated_permissions=None, parent_agent=None):
        self.agent_id = agent_id
        self.tools = set(tools or ['read'])
        if delegated_permissions is None:
            self.delegated_permissions = {'read'}
        else:
            self.delegated_permissions = set(delegated_permissions)
        self.parent_agent = parent_agent

    def propose(self, action, resource):
        return {
            'agent_id': self.agent_id,
            'action': action,
            'resource': resource,
            'tools': sorted(list(self.tools)),
            'delegated_permissions': sorted(list(self.delegated_permissions)),
            'parent_agent': self.parent_agent,
        }


AGENT_REGISTRY = {
    'agent_main': {
        'tools': {'read', 'reschedule', 'delete'},
        'delegated_permissions': {'read', 'reschedule'},
        'parent_agent': None,
    },
    'agent_helper': {
        'tools': {'read', 'reschedule', 'delete'},
        'delegated_permissions': {'read'},
        'parent_agent': 'agent_main',
    },
    'agent_helper2': {
        'tools': {'read'},
        'delegated_permissions': {'read', 'reschedule'},
        'parent_agent': 'agent_main',
    },
}

class AuthorizationBoundary:
    def __init__(self, policy, calendar, audit, agent_registry=None):
        self.policy = policy
        self.calendar = calendar
        self.audit = audit
        self.agent_registry = agent_registry if agent_registry is not None else AGENT_REGISTRY

    def authorize(self, request, use_trusted_registry=True):
        req_id = request.get('request_id') or str(uuid.uuid4())
        scenario = request.get('scenario', 'unknown')
        agent_id = request.get('agent_id', 'agent_main')
        action = request.get('action')
        resource = request.get('resource')
        if use_trusted_registry:
            if agent_id not in self.agent_registry:
                return {
                    'request_id': req_id,
                    'scenario': scenario,
                    'agent_id': agent_id,
                    'action': action,
                    'resource': resource,
                    'decision': 'DENY',
                    'reason': 'unknown_agent_rejected',
                    'policy_snapshot': self.policy.snapshot(),
                    'policy_version': self.policy.version,
                }
            reg = self.agent_registry[agent_id]
            agent_tools = set(reg.get('tools') or [])
            delegated_perms = set(reg.get('delegated_permissions') or [])
            parent_agent = reg.get('parent_agent')
        else:
            agent_tools = set(request.get('tools') or [])
            delegated_perms = set(request.get('delegated_permissions') or [])
            parent_agent = request.get('parent_agent')

        decision = None
        reason = ''

        if action in {'reschedule', 'delete'} and action not in agent_tools:
            decision = 'DENY'
            reason = 'tool_unavailable:' + str(action)
        elif action == 'read' and len(agent_tools) > 0 and 'read' not in agent_tools:
            decision = 'DENY'
            reason = 'tool_unavailable:read'

        if decision is None:
            if agent_id != 'agent_main':
                if not delegated_perms or action not in delegated_perms:
                    decision = 'DENY'
                    reason = 'delegation_exceeds:' + str(action)
            else:
                if delegated_perms and len(delegated_perms) > 0 and action not in delegated_perms:
                    decision = 'DENY'
                    reason = 'delegation_exceeds:' + str(action)

        if decision is None:
            if action in self.policy.revoked:
                decision = 'DENY'
                reason = 'permission_revoked:' + str(action)
            elif action in self.policy.prohibited_actions:
                decision = 'DENY'
                reason = 'prohibited:' + str(action)
            elif action not in self.policy.permitted_actions:
                decision = 'DENY'
                reason = 'not_permitted:' + str(action)
            elif resource in self.policy.protected_resources and action in {'reschedule', 'delete'}:
                decision = 'DENY'
                reason = 'protected_resource:' + str(resource)
            elif action in self.policy.requires_approval:
                decision = 'DENY'
                reason = 'requires_human_approval:' + str(action)
            else:
                decision = 'ALLOW'
                reason = 'policy_permit'

        if decision is None:
            decision = 'DENY'
            reason = 'unknown'

        return {
            'request_id': req_id,
            'scenario': scenario,
            'agent_id': agent_id,
            'action': action,
            'resource': resource,
            'tools_available': sorted(list(agent_tools)),
            'delegated_permissions': sorted(list(delegated_perms)),
            'parent_agent': parent_agent,
            'decision': decision,
            'reason': reason,
            'policy_snapshot': self.policy.snapshot(),
            'policy_version': self.policy.version,
        }

    def enforce(self, request, revalidate_at_execution=False, use_trusted_registry=True):
        req_id = request.get('request_id') or str(uuid.uuid4())
        scenario = request.get('scenario', 'unknown')
        agent_id = request.get('agent_id', 'agent_main')
        action = request.get('action')
        resource = request.get('resource')
        if use_trusted_registry:
            if agent_id not in self.agent_registry:
                state_before = self.calendar.get_state()
                outcome_state = self.calendar.get_state()
                entry = {
                    'request_id': req_id,
                    'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'scenario': scenario,
                    'agent_id': agent_id,
                    'parent_agent': None,
                    'action': action,
                    'resource': resource,
                    'tools_available': [],
                    'delegated_permissions': [],
                    'decision': 'DENY',
                    'original_decision': 'DENY',
                    'original_policy_version': self.policy.version,
                    'policy_version_at_execution': self.policy.version,
                    'reason': 'unknown_agent_rejected',
                    'policy_snapshot': self.policy.snapshot(),
                    'executed': False,
                    'revalidated_at_execution': bool(revalidate_at_execution),
                    'state_before': state_before,
                    'state_after': outcome_state,
                }
                self.audit.log(entry)
                return entry
            reg = self.agent_registry[agent_id]
            agent_tools = set(reg.get('tools') or [])
            delegated_perms = set(reg.get('delegated_permissions') or [])
            parent_agent = reg.get('parent_agent')
        else:
            agent_tools = set(request.get('tools') or [])
            delegated_perms = set(request.get('delegated_permissions') or [])
            parent_agent = request.get('parent_agent')

        state_before = self.calendar.get_state()
        decision = None
        reason = ''
        executed = False
        original_decision = None
        original_policy_version = self.policy.version

        if action in {'reschedule', 'delete'} and action not in agent_tools:
            decision = 'DENY'
            reason = 'tool_unavailable:' + str(action)
        elif action == 'read' and len(agent_tools) > 0 and 'read' not in agent_tools:
            decision = 'DENY'
            reason = 'tool_unavailable:read'

        if decision is None:
            if agent_id != 'agent_main':
                if not delegated_perms or action not in delegated_perms:
                    decision = 'DENY'
                    reason = 'delegation_exceeds:' + str(action)
            else:
                if delegated_perms and len(delegated_perms) > 0 and action not in delegated_perms:
                    decision = 'DENY'
                    reason = 'delegation_exceeds:' + str(action)

        if decision is None:
            if action in self.policy.revoked:
                decision = 'DENY'
                reason = 'permission_revoked:' + str(action)
            elif action in self.policy.prohibited_actions:
                decision = 'DENY'
                reason = 'prohibited:' + str(action)
            elif action not in self.policy.permitted_actions:
                decision = 'DENY'
                reason = 'not_permitted:' + str(action)
            elif resource in self.policy.protected_resources and action in {'reschedule', 'delete'}:
                decision = 'DENY'
                reason = 'protected_resource:' + str(resource)
            elif action in self.policy.requires_approval:
                decision = 'DENY'
                reason = 'requires_human_approval:' + str(action)
            else:
                decision = 'ALLOW'
                reason = 'policy_permit'

        if decision is None:
            decision = 'DENY'
            reason = 'unknown'

        if original_decision is None:
            original_decision = decision

        if decision == 'ALLOW' and revalidate_at_execution:
            if action in self.policy.revoked:
                decision = 'DENY'
                reason = 'revalidated_permission_revoked:' + str(action)
            elif resource in self.policy.protected_resources and action in {'reschedule', 'delete'}:
                decision = 'DENY'
                reason = 'revalidated_protected_resource:' + str(resource)
            elif action not in self.policy.permitted_actions:
                decision = 'DENY'
                reason = 'revalidated_not_permitted:' + str(action)

        if decision == 'ALLOW':
            try:
                if action == 'read':
                    self.calendar.read(resource)
                    executed = True
                elif action == 'reschedule':
                    self.calendar.reschedule(resource)
                    executed = True
                elif action == 'delete':
                    self.calendar.delete(resource)
                    executed = True
                else:
                    decision = 'DENY'
                    reason = 'unknown_action:' + str(action)
                    executed = False
            except Exception:
                decision = 'DENY'
                reason = 'enforcement_error'
                executed = False

        outcome_state = self.calendar.get_state()
        entry = {
            'request_id': req_id,
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'scenario': scenario,
            'agent_id': agent_id,
            'parent_agent': parent_agent,
            'action': action,
            'resource': resource,
            'tools_available': sorted(list(agent_tools)),
            'delegated_permissions': sorted(list(delegated_perms)),
            'decision': decision,
            'original_decision': original_decision,
            'original_policy_version': original_policy_version,
            'policy_version_at_execution': self.policy.version,
            'reason': reason,
            'policy_snapshot': self.policy.snapshot(),
            'executed': executed,
            'revalidated_at_execution': bool(revalidate_at_execution),
            'state_before': state_before,
            'state_after': outcome_state,
        }
        self.audit.log(entry)
        return entry

class TestRunner:
    def __init__(self):
        self.results = []
        self.unexpected_mutations = 0
        self.unexpected_allows = 0
        self.unexpected_denies = 0

    def _count_mutations(self, before, after):
        mutations = 0
        all_keys = set(before.keys()) | set(after.keys())
        for k in all_keys:
            if before.get(k) != after.get(k):
                mutations += 1
        return mutations

    def run(self):
        print('=' * 60)
        print('AuthorityCheck - Agent Authority Continuity Tests')
        print('=' * 60)
        self._exp1_baseline()
        self._exp2_revocation()
        self._exp3_capability()
        self._exp4_delegation()
        self._exp5_toctou()
        self._report()

    def _exp1_baseline(self):
        print('\n[EXP1] Baseline Authorization')
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator('agent_main', tools=['read', 'reschedule'], delegated_permissions=['read', 'reschedule'])
        req = agent.propose('reschedule', 'ev1')
        req['scenario'] = 'exp1_permitted_reschedule'
        res = boundary.enforce(req)
        expected = 'ALLOW'
        muts = self._count_mutations(res['state_before'], res['state_after'])
        if res['decision'] != 'ALLOW' or not res['executed']:
            if muts > 0:
                self.unexpected_mutations += muts
        ok = (res['decision'] == expected and res['executed'] == True)
        self._record('exp1_permitted_reschedule', expected, res, ok)
        req2 = agent.propose('reschedule', 'ev2')
        req2['scenario'] = 'exp1_protected_denied'
        res2 = boundary.enforce(req2)
        expected2 = 'DENY'
        muts2 = self._count_mutations(res2['state_before'], res2['state_after'])
        if res2['decision'] == 'DENY' and not res2['executed'] and muts2 > 0:
            self.unexpected_mutations += muts2
        ok2 = (res2['decision'] == expected2 and res2['executed'] == False and muts2 == 0)
        self._record('exp1_protected_denied', expected2, res2, ok2)

    def _exp2_revocation(self):
        print('\n[EXP2] Permission Revocation')
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator('agent_main', tools=['read', 'reschedule'], delegated_permissions=['read', 'reschedule'])
        req = agent.propose('reschedule', 'ev1')
        req['scenario'] = 'exp2_before_revoke'
        res = boundary.enforce(req)
        expected = 'ALLOW'
        ok = (res['decision'] == expected and res['executed'] == True)
        self._record('exp2_before_revoke', expected, res, ok)
        policy.revoke('reschedule')
        req2 = agent.propose('reschedule', 'ev1')
        req2['scenario'] = 'exp2_after_revoke'
        res2 = boundary.enforce(req2)
        expected2 = 'DENY'
        muts = self._count_mutations(res2['state_before'], res2['state_after'])
        if muts > 0:
            self.unexpected_mutations += muts
        ok2 = (res2['decision'] == expected2 and res2['executed'] == False and muts == 0)
        self._record('exp2_after_revoke', expected2, res2, ok2)

    def _exp3_capability(self):
        print('\n[EXP3] Capability Expansion Without Permission')
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator('agent_main', tools=['read', 'reschedule', 'delete'], delegated_permissions=['read', 'reschedule'])
        req = agent.propose('delete', 'ev1')
        req['scenario'] = 'exp3_delete_tool_no_perm'
        res = boundary.enforce(req)
        expected = 'DENY'
        muts = self._count_mutations(res['state_before'], res['state_after'])
        if muts > 0:
            self.unexpected_mutations += muts
        ok = (res['decision'] == expected and res['executed'] == False and muts == 0)
        self._record('exp3_delete_tool_no_perm', expected, res, ok)

    def _exp4_delegation(self):
        print('\n[EXP4] Multi-Agent Delegation')
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        helper = AgentSimulator('agent_helper', tools=['read', 'reschedule', 'delete'], delegated_permissions=['read'], parent_agent='agent_main')
        req = helper.propose('delete', 'ev1')
        req['scenario'] = 'exp4_helper_delete_denied_by_delegation'
        res = boundary.enforce(req)
        expected = 'DENY'
        muts = self._count_mutations(res['state_before'], res['state_after'])
        if muts > 0:
            self.unexpected_mutations += muts
        ok = (res['decision'] == expected and res['executed'] == False and muts == 0)
        self._record('exp4_helper_delete_denied_by_delegation', expected, res, ok)
        helper2 = AgentSimulator('agent_helper2', tools=['read'], delegated_permissions=['read', 'reschedule'], parent_agent='agent_main')
        req2 = helper2.propose('reschedule', 'ev1')
        req2['scenario'] = 'exp4_helper_tool_unavailable'
        res2 = boundary.enforce(req2)
        expected2 = 'DENY'
        muts2 = self._count_mutations(res2['state_before'], res2['state_after'])
        if muts2 > 0:
            self.unexpected_mutations += muts2
        ok2 = (res2['decision'] == expected2 and res2['executed'] == False and muts2 == 0)
        self._record('exp4_helper_tool_unavailable', expected2, res2, ok2)

    def _exp5_toctou(self):
        print('\n[EXP5] TOCTOU (deterministic simulation)')
        policy = Policy()
        cal = ProtectedCalendar()
        audit = AuditLog()
        boundary = AuthorizationBoundary(policy, cal, audit)
        agent = AgentSimulator('agent_main')
        req = agent.propose('reschedule', 'ev1')
        req['scenario'] = 'exp5_toctou_initial_authorize'
        auth = boundary.authorize(req)
        cached_decision = auth['decision']
        cached_policy_ver = auth['policy_version']
        cached_state = {k: dict(v) for k, v in cal.events.items()}
        policy.revoke('reschedule')
        if cached_decision == 'ALLOW':
            try:
                cal.reschedule('ev1')
                executed_stale = True
            except Exception:
                executed_stale = False
        else:
            executed_stale = False
        state_after_stale = cal.get_state()
        res_stale = {
            'decision': 'ALLOW' if executed_stale else 'DENY',
            'reason': 'stale_authorized_executed' if executed_stale else 'stale_blocked',
            'executed': executed_stale,
            'state_before': cached_state,
            'state_after': state_after_stale,
        }
        expected_stale = 'ALLOW'
        muts_stale = self._count_mutations(cached_state, res_stale['state_after'])
        decision_ok = (res_stale['decision'] == expected_stale)
        ok_stale = (res_stale['decision'] == expected_stale and res_stale['executed'] == True and muts_stale >= 1)
        passed_stale = decision_ok and ok_stale
        self.results.append({'name': 'exp5_toctou_stale_no_reval', 'expected': expected_stale, 'actual_decision': res_stale['decision'], 'reason': res_stale['reason'], 'executed': res_stale['executed'], 'decision_correct': decision_ok, 'outcome_correct': ok_stale, 'passed': passed_stale})
        print('  %s: %s -> %s (%s)' % ('PASS' if passed_stale else 'FAIL', 'exp5_toctou_stale_no_reval', res_stale['decision'], res_stale['reason']))
        policy2 = Policy()
        cal2 = ProtectedCalendar()
        audit2 = AuditLog()
        boundary2 = AuthorizationBoundary(policy2, cal2, audit2)
        agent2 = AgentSimulator('agent_main')
        req2 = agent2.propose('reschedule', 'ev1')
        req2['scenario'] = 'exp5_toctou_with_reval'
        auth2 = boundary2.authorize(req2)
        state_init2 = {k: dict(v) for k, v in cal2.events.items()}
        policy2.revoke('reschedule')
        res2 = boundary2.enforce(req2, revalidate_at_execution=True)
        expected2 = 'DENY'
        muts2 = self._count_mutations(state_init2, res2['state_after'])
        if res2['decision'] == 'DENY' and not res2['executed'] and muts2 > 0:
            self.unexpected_mutations += muts2
        ok2 = (res2['decision'] == expected2 and res2['executed'] == False and muts2 == 0)
        self._record('exp5_toctou_with_reval', expected2, res2, ok2)
    def _record(self, name, expected, res, ok):
        decision_ok = (res['decision'] == expected)
        if res['decision'] == 'ALLOW' and expected == 'DENY':
            self.unexpected_allows += 1
        if res['decision'] == 'DENY' and expected == 'ALLOW':
            self.unexpected_denies += 1
        self.results.append({'name': name, 'expected': expected, 'actual_decision': res['decision'], 'reason': res['reason'], 'executed': res['executed'], 'decision_correct': decision_ok, 'outcome_correct': ok, 'passed': decision_ok and ok})
        print('  %s: %s -> %s (%s)' % ('PASS' if (decision_ok and ok) else 'FAIL', name, res['decision'], res['reason']))

    def _report(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if r['passed'])
        print('\n' + '=' * 60)
        print('Results: %d/%d passed (%.1f%%)' % (passed, total, (passed/total*100) if total else 0))
        print('Unexpected ALLOWs: %d' % self.unexpected_allows)
        print('Unexpected DENYs: %d' % self.unexpected_denies)
        print('Unauthorized mutations detected: %d' % self.unexpected_mutations)
        print('=' * 60)
        report = {'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'), 'summary': {'total': total, 'passed': passed, 'failed': total - passed, 'pass_rate': passed/total if total else 0, 'unexpected_allows': self.unexpected_allows, 'unexpected_denies': self.unexpected_denies, 'unauthorized_mutations': self.unexpected_mutations}, 'results': self.results, 'notes': 'All results are local simulation results only.'}
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORTS_DIR / ('authoritycheck_report_' + str(int(time.time())) + '.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print('\nReport: ' + str(report_path))


def main():
    TestRunner().run()


if __name__ == '__main__':
    main()
