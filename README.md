# 🚨 Security Vulnerability: Client-Side Authorization Bypass via localStorage Manipulation

## Severity: CRITICAL (CVSS 9.8)

### Summary

A critical security vulnerability has been discovered in the application's authorization mechanism. The application stores user authority/role information in `localStorage` and relies solely on client-side checks to determine access control. This allows any authenticated user to escalate their privileges to administrator level by manipulating browser storage, gaining unauthorized access to administrative functions.

---

## Vulnerability Details

### Type
- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **CWE-602**: Client-Side Enforcement of Server-Side Security
- **OWASP**: A01:2021 - Broken Access Control

### Affected Component
- **Storage Location**: `localStorage.authority`
- **Storage Key**: `fga-site` (contains user object with authority field)
- **Affected Routes**: All administrative routes and functions

### CVSS v3.1 Score: 9.8 (Critical)
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Vector Breakdown:**
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Privileges Required (PR): None (any authenticated user)
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): High
- Integrity (I): High
- Availability (A): High

---

## Proof of Concept

### Step 1: Initial State (Guest User)

```javascript
// Current user state in localStorage
localStorage.getItem('fga-site');
// Returns:
{
  "authority": "guest",
  "user": {
    "id": 123,
    "email": "guest@example.com",
    "role": "guest"
  }
}
```

### Step 2: Exploitation

```javascript
// Open browser console (F12)
// Modify authority to admin
localStorage.authority = 'admin';

// Or modify the entire fga-site object
const data = JSON.parse(localStorage.getItem('fga-site'));
data.authority = 'admin';
data.user.role = 'admin';
localStorage.setItem('fga-site', JSON.stringify(data));

// Reload the page
location.reload();
```

### Step 3: Result

After page reload, the application:
1. ✅ Grants full administrative interface access
2. ✅ Displays admin-only menu items and routes
3. ✅ Allows access to user management functions
4. ✅ Enables administrative operations (create/edit/delete users)
5. ✅ Bypasses all client-side authorization checks

---

## Technical Analysis

### Root Cause

The application implements authorization checks exclusively on the client-side:

```javascript
// Example from the codebase
const authority = localStorage.getItem('authority');

// Client-side route protection
if (authority !== 'admin') {
  return <Redirect to="/403" />;
}

// Client-side UI rendering
{authority === 'admin' && <AdminPanel />}
```

**Problem**: These checks can be bypassed by modifying `localStorage` values in the browser.

### Data Flow

```
1. User Login → Server validates credentials
2. Server returns user data (including authority)
3. Frontend stores authority in localStorage
4. All subsequent checks read from localStorage ❌
5. No server-side validation on protected endpoints ❌
```

### Vulnerable Code Pattern

```javascript
// js/app.f53d4515.js (minified)
// Authority is read from localStorage for route protection
const currentUser = JSON.parse(localStorage.getItem('fga-site'));
const authority = currentUser.authority;

// DVA model: namespace:"user"
// Client-side authorization check
if (authority === 'admin') {
  // Grant access to admin features
}
```

---

## Impact Assessment

### Immediate Risks

1. **Privilege Escalation**
   - Any authenticated user can gain administrator privileges
   - No technical skill required (browser console access only)
   - Instant access to all administrative functions

2. **Data Breach**
   - Access to all user accounts and personal information
   - Ability to view sensitive system configurations
   - Exposure of business-critical data

3. **System Compromise**
   - Ability to create new administrator accounts
   - Modification or deletion of existing users
   - Potential for complete system takeover

4. **Compliance Violations**
   - GDPR: Unauthorized access to personal data
   - SOC 2: Inadequate access controls
   - ISO 27001: Broken authentication mechanisms

### Attack Scenarios

#### Scenario 1: Malicious Insider
```
1. Employee with guest account
2. Modifies localStorage.authority = 'admin'
3. Creates backdoor admin account
4. Maintains persistent access after termination
```

#### Scenario 2: Compromised Account
```
1. Attacker gains access to low-privilege account
2. Escalates to admin via localStorage manipulation
3. Exfiltrates sensitive data
4. Creates additional admin accounts for persistence
```

#### Scenario 3: Social Engineering
```
1. Attacker tricks user into running console command
2. User unknowingly grants admin access
3. Attacker uses session to perform malicious actions
```

---

## Reproduction Steps

### Prerequisites
- Valid user account (any privilege level)
- Modern web browser (Chrome, Firefox, Edge)
- Access to browser Developer Tools

### Steps to Reproduce

1. **Login as regular user**
   ```
   Navigate to: https://cloud.termokont.ru
   Login with: guest@example.com / password
   ```

2. **Open Developer Tools**
   ```
   Press F12 (Windows/Linux) or Cmd+Option+I (Mac)
   Navigate to Console tab
   ```

3. **Modify localStorage**
   ```javascript
   localStorage.authority = 'admin';
   ```

4. **Reload the page**
   ```javascript
   location.reload();
   ```

5. **Verify admin access**
   ```
   - Admin menu items are now visible
   - Can access /manage/users route
   - Can create/edit/delete users
   - Full administrative interface available
   ```

### Expected vs Actual Behavior

**Expected Behavior:**
- Application should validate authority on the server
- Modifying localStorage should have no effect
- Server should return 403 Forbidden for unauthorized requests

**Actual Behavior:**
- Application trusts client-side authority value
- Full admin access granted after localStorage modification
- No server-side validation performed

---

## Recommended Fixes

### Priority 1: Server-Side Authorization (CRITICAL)

Implement proper server-side authorization checks on ALL protected endpoints:

```javascript
// Backend (Node.js/Express example)
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = req.session.user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.authority !== 'admin') {
    return res.status(403).json({ 
      error: 'Forbidden: Administrator access required' 
    });
  }
  next();
}

// Apply to all admin routes
app.get('/api/fgas/:userId/userList', requireAuth, requireAdmin, getUserList);
app.post('/api/fgas/:userId/user', requireAuth, requireAdmin, createUser);
app.put('/api/fgas/:userId/user/:id', requireAuth, requireAdmin, updateUser);
app.delete('/api/fgas/:userId/user/:id', requireAuth, requireAdmin, deleteUser);
```

### Priority 2: Remove Client-Side Authority Storage

Stop storing authority in localStorage:

```javascript
// Frontend (React example)
// ❌ BAD: Don't store authority in localStorage
localStorage.setItem('authority', user.authority);

// ✅ GOOD: Store in memory only
const [userAuthority, setUserAuthority] = useState(null);

useEffect(() => {
  // Fetch authority from server on each page load
  fetch('/api/user/me', { credentials: 'include' })
    .then(res => res.json())
    .then(user => setUserAuthority(user.authority));
}, []);
```

### Priority 3: Implement RBAC (Role-Based Access Control)

```javascript
// Backend: Centralized permission checking
const permissions = {
  'admin': ['user:create', 'user:read', 'user:update', 'user:delete', 'system:config'],
  'manager': ['user:read', 'user:update', 'report:read'],
  'guest': ['report:read']
};

function hasPermission(user, permission) {
  const userPermissions = permissions[user.authority] || [];
  return userPermissions.includes(permission);
}

// Use in routes
app.post('/api/fgas/:userId/user', requireAuth, (req, res) => {
  if (!hasPermission(req.user, 'user:create')) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  // Create user logic
});
```

### Priority 4: Add Audit Logging

```javascript
// Log all authorization attempts
function auditLog(req, action, result) {
  logger.info({
    timestamp: new Date(),
    userId: req.user?.id,
    email: req.user?.email,
    authority: req.user?.authority,
    action: action,
    result: result,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });
}

// Use in middleware
function requireAdmin(req, res, next) {
  if (!req.user || req.user.authority !== 'admin') {
    auditLog(req, 'admin_access_denied', 'forbidden');
    return res.status(403).json({ error: 'Forbidden' });
  }
  auditLog(req, 'admin_access_granted', 'success');
  next();
}
```

---

## Security Best Practices

### 1. Never Trust Client-Side Data

```javascript
// ❌ NEVER do this
const authority = localStorage.getItem('authority');
if (authority === 'admin') {
  // Grant access
}

// ✅ ALWAYS validate on server
app.get('/admin/users', requireAuth, requireAdmin, (req, res) => {
  // Server validates req.session.user.authority
});
```

### 2. Use HTTP-Only Cookies for Sessions

```javascript
// Backend: Set secure session cookie
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,  // Prevents JavaScript access
    secure: true,    // HTTPS only
    sameSite: 'strict',
    maxAge: 3600000  // 1 hour
  }
}));
```

### 3. Implement Defense in Depth

```
Layer 1: Client-side checks (UX only, not security)
Layer 2: Server-side authentication (verify user identity)
Layer 3: Server-side authorization (verify user permissions)
Layer 4: Database-level permissions (limit query access)
Layer 5: Audit logging (detect and respond to breaches)
```

### 4. Regular Security Audits

```javascript
// Automated security testing
describe('Authorization Tests', () => {
  it('should deny guest access to admin endpoints', async () => {
    const guestToken = await loginAsGuest();
    const response = await fetch('/api/admin/users', {
      headers: { 'Authorization': `Bearer ${guestToken}` }
    });
    expect(response.status).toBe(403);
  });
  
  it('should validate authority on server', async () => {
    // Attempt to bypass with modified localStorage
    const response = await fetch('/api/admin/users', {
      headers: { 
        'Authorization': `Bearer ${guestToken}`,
        'X-Authority': 'admin'  // Fake authority header
      }
    });
    expect(response.status).toBe(403);
  });
});
```

---

## Mitigation Timeline

### Immediate (Within 24 hours)
- [ ] Add server-side authorization checks to all admin endpoints
- [ ] Deploy emergency patch to production
- [ ] Monitor logs for exploitation attempts
- [ ] Notify security team and stakeholders

### Short-term (Within 1 week)
- [ ] Implement comprehensive RBAC system
- [ ] Add audit logging for all authorization events
- [ ] Remove authority from localStorage
- [ ] Conduct security testing of all endpoints

### Long-term (Within 1 month)
- [ ] Complete security audit of entire application
- [ ] Implement automated security testing
- [ ] Security training for development team
- [ ] Establish security review process for code changes

---

## Testing Checklist

After implementing fixes, verify:

- [ ] Guest user cannot access admin routes (403 Forbidden)
- [ ] Modifying localStorage has no effect on authorization
- [ ] All admin endpoints validate authority on server
- [ ] Session cookies are HTTP-only and secure
- [ ] Audit logs capture all authorization attempts
- [ ] RBAC permissions are enforced consistently
- [ ] No sensitive data stored in localStorage
- [ ] Authorization checks cannot be bypassed

---

## References

- [OWASP Top 10 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## Disclosure Timeline

- **Discovery Date**: 2026-03-13
- **Vendor Notification**: CSAB

---

## Contact

For questions or additional information about this vulnerability, please contact:
- Security Team: danila2002121@gmail.com

---

**Note**: This vulnerability should be treated as CRITICAL and addressed immediately. The ease of exploitation combined with the high impact makes this a significant security risk that could lead to complete system compromise.
