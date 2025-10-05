# BÁO CÁO THIẾT KẾ MODULE 3: USER INTERFACE & AUTHENTICATION MODULE

**Sinh viên thực hiện:** [Tên bạn]
**Mã sinh viên:** [MSSV]
**Lớp:** [Tên lớp]

---

## 1. TỔNG QUAN MODULE

### 1.1. Vai trò trong hệ thống
Module 3 đóng vai trò **giao diện người dùng và xác thực** cho hệ thống chatbot. Module này bao gồm:
- **Client 1 (Admin UI)**: Giao diện quản trị cho Admin
- **Client 2 (Customer UI)**: Giao diện chat cho người dùng cuối
- **Authentication Service**: Xác thực và phân quyền người dùng
- **User Management**: Quản lý tài khoản người dùng

### 1.2. Chức năng chính

#### Client 1 - Admin UI:
1. **Training Data Management UI**: Quản lý labels, samples, QA pairs
2. **Model Management UI**: Xem danh sách models, trigger training, deploy
3. **Document Management UI**: Upload documents, xem trạng thái sync
4. **Analytics Dashboard**: Thống kê, charts, reports

#### Client 2 - Customer UI:
1. **User Authentication**: Đăng ký, đăng nhập, quên mật khẩu
2. **Chat Interface**: Giao diện hỏi đáp real-time
3. **Conversation History**: Lịch sử hội thoại
4. **User Profile**: Quản lý thông tin cá nhân

#### Authentication Service:
1. **User Registration & Login**: JWT-based authentication
2. **Role-Based Access Control**: Admin vs Customer roles
3. **Session Management**: Token refresh, logout
4. **Password Management**: Reset password, change password

### 1.3. Công nghệ sử dụng

#### Frontend:
- **Framework**: React / Vue.js / Streamlit
- **State Management**: Redux / Vuex / React Context
- **HTTP Client**: Axios / Fetch API
- **WebSocket**: Socket.io (real-time chat)
- **UI Library**: Material-UI / Ant Design / Tailwind CSS

#### Backend (Auth Service):
- **Framework**: Flask / FastAPI
- **Authentication**: JWT (JSON Web Tokens)
- **Password Hashing**: bcrypt / argon2
- **Database**: PostgreSQL / MySQL
- **Session Store**: Redis (optional)

---

## 2. THIẾT KẾ CƠ SỞ DỮ LIỆU

### 2.1. User Management Schema (PostgreSQL)

#### Table: `users`
```sql
CREATE TABLE users (
    user_id VARCHAR(36) PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role VARCHAR(20) DEFAULT 'customer', -- 'admin' or 'customer'
    phone VARCHAR(20),
    avatar_url VARCHAR(500),
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'inactive', 'banned'
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
```

#### Table: `refresh_tokens`
```sql
CREATE TABLE refresh_tokens (
    token_id SERIAL PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(user_id) ON DELETE CASCADE,
    refresh_token VARCHAR(500) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(refresh_token);
```

#### Table: `password_reset_tokens`
```sql
CREATE TABLE password_reset_tokens (
    token_id SERIAL PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(user_id) ON DELETE CASCADE,
    reset_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used BOOLEAN DEFAULT FALSE
);
```

### 2.2. User Activity Schema

#### Table: `login_history`
```sql
CREATE TABLE login_history (
    log_id SERIAL PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(user_id),
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    failure_reason VARCHAR(255)
);

CREATE INDEX idx_login_history_user ON login_history(user_id);
CREATE INDEX idx_login_history_time ON login_history(login_time);
```

#### Table: `user_sessions`
```sql
CREATE TABLE user_sessions (
    session_id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(user_id) ON DELETE CASCADE,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    active BOOLEAN DEFAULT TRUE
);
```

### 2.3. User Preferences Schema

#### Table: `user_preferences`
```sql
CREATE TABLE user_preferences (
    preference_id SERIAL PRIMARY KEY,
    user_id VARCHAR(36) UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
    language VARCHAR(10) DEFAULT 'vi',
    theme VARCHAR(20) DEFAULT 'light', -- 'light', 'dark'
    notifications_enabled BOOLEAN DEFAULT TRUE,
    email_notifications BOOLEAN DEFAULT TRUE,
    preferences JSONB, -- Additional custom preferences
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 3. THIẾT KẾ LỚP THỰC THỂ (CLASS DIAGRAM)

### 3.1. Entity Classes

```mermaid
classDiagram
    class User {
        +String userId
        +String username
        +String email
        +String passwordHash
        +String fullName
        +String role
        +String phone
        +String avatarUrl
        +String status
        +bool emailVerified
        +DateTime createdAt
        +DateTime lastLogin
        +checkPassword(password) bool
        +setPassword(password) void
        +toDict() dict
        +toPublicDict() dict
    }

    class RefreshToken {
        +int tokenId
        +String userId
        +String refreshToken
        +DateTime expiresAt
        +bool revoked
        +isValid() bool
        +revoke() void
    }

    class Session {
        +String sessionId
        +String userId
        +DateTime startedAt
        +DateTime lastActivity
        +String ipAddress
        +String userAgent
        +bool active
        +isExpired() bool
        +terminate() void
    }

    class UserPreferences {
        +int preferenceId
        +String userId
        +String language
        +String theme
        +bool notificationsEnabled
        +bool emailNotifications
        +Map preferences
        +update(data) void
    }

    class LoginHistory {
        +int logId
        +String userId
        +DateTime loginTime
        +String ipAddress
        +String userAgent
        +bool success
        +String failureReason
    }

    User "1" --> "*" RefreshToken
    User "1" --> "*" Session
    User "1" --> "1" UserPreferences
    User "1" --> "*" LoginHistory
```

---

## 4. THIẾT KẾ CHI TIẾT CÁC CHỨC NĂNG

---

## CHỨC NĂNG 1: USER AUTHENTICATION

### 4.1.1. Mô tả
Xác thực người dùng với JWT tokens, bao gồm đăng ký, đăng nhập, refresh token, logout.

### 4.1.2. Thiết kế giao diện API

#### Endpoint 1: `POST /api/v1/auth/register`
Đăng ký tài khoản mới

**Request:**
```json
{
    "username": "nguyenvana",
    "email": "nguyenvana@example.com",
    "password": "SecurePass123!",
    "full_name": "Nguyễn Văn A",
    "phone": "0912345678"
}
```

**Response:**
```json
{
    "success": true,
    "message": "User registered successfully. Please verify your email.",
    "data": {
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "username": "nguyenvana",
        "email": "nguyenvana@example.com",
        "role": "customer"
    }
}
```

#### Endpoint 2: `POST /api/v1/auth/login`
Đăng nhập

**Request:**
```json
{
    "email": "nguyenvana@example.com",
    "password": "SecurePass123!"
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "user": {
            "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "username": "nguyenvana",
            "email": "nguyenvana@example.com",
            "full_name": "Nguyễn Văn A",
            "role": "customer",
            "avatar_url": null
        }
    }
}
```

#### Endpoint 3: `POST /api/v1/auth/refresh`
Refresh access token

**Request:**
```json
{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "expires_in": 3600
    }
}
```

#### Endpoint 4: `POST /api/v1/auth/logout`
Logout (revoke tokens)

**Request Header:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response:**
```json
{
    "success": true,
    "message": "Logged out successfully"
}
```

#### Endpoint 5: `POST /api/v1/auth/verify-token`
Verify JWT token (dùng bởi Server 2)

**Request:**
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "valid": true,
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "username": "nguyenvana",
        "role": "customer",
        "expires_at": "2025-01-15T14:30:00Z"
    }
}
```

### 4.1.3. Thiết kế giao diện UI

#### UI 1: Login Screen
```
┌─────────────────────────────────────┐
│         PTIT Chatbot Login          │
├─────────────────────────────────────┤
│                                     │
│  Email:    [________________]       │
│                                     │
│  Password: [________________]       │
│                                     │
│  [ ] Remember me                    │
│                                     │
│       [      Login      ]           │
│                                     │
│  Don't have account? Register       │
│  Forgot password?                   │
└─────────────────────────────────────┘
```

#### UI 2: Register Screen
```
┌─────────────────────────────────────┐
│      PTIT Chatbot Registration      │
├─────────────────────────────────────┤
│                                     │
│  Full Name:  [________________]     │
│  Username:   [________________]     │
│  Email:      [________________]     │
│  Phone:      [________________]     │
│  Password:   [________________]     │
│  Confirm:    [________________]     │
│                                     │
│  [ ] I agree to Terms & Conditions  │
│                                     │
│       [    Register    ]            │
│                                     │
│  Already have account? Login        │
└─────────────────────────────────────┘
```

### 4.1.4. Biểu đồ lớp chi tiết

```mermaid
classDiagram
    class AuthService {
        -Database db
        -JWTManager jwtManager
        -PasswordHasher hasher
        -EmailService emailService
        +register(userData) User
        +login(email, password) AuthResult
        +logout(userId, token) bool
        +refreshToken(refreshToken) String
        +verifyToken(token) TokenPayload
        +resetPassword(email) bool
        +changePassword(userId, oldPass, newPass) bool
    }

    class JWTManager {
        -String secretKey
        -int accessTokenExpiry
        -int refreshTokenExpiry
        +generateAccessToken(userId, role) String
        +generateRefreshToken(userId) String
        +verifyToken(token) TokenPayload
        +decodeToken(token) Map
        +isTokenExpired(token) bool
    }

    class PasswordHasher {
        -int saltRounds
        +hashPassword(password) String
        +verifyPassword(password, hash) bool
        +validatePasswordStrength(password) ValidationResult
    }

    class SessionManager {
        -Database db
        -Redis cache
        +createSession(userId, metadata) Session
        +getSession(sessionId) Session
        +updateActivity(sessionId) void
        +terminateSession(sessionId) void
        +getUserSessions(userId) List~Session~
    }

    class EmailService {
        -SMTPConfig config
        +sendVerificationEmail(user, token) bool
        +sendPasswordResetEmail(user, token) bool
        +sendWelcomeEmail(user) bool
    }

    AuthService --> JWTManager
    AuthService --> PasswordHasher
    AuthService --> SessionManager
    AuthService --> EmailService
```

**Giải thích:**

1. **AuthService** (Main authentication service)
   - `register()`: Đăng ký user mới, hash password, send verification email
   - `login()`: Verify credentials, generate JWT tokens
   - `verifyToken()`: Verify token cho Server 2
   - `resetPassword()`: Generate reset token, send email

2. **JWTManager** (JWT token management)
   - `generateAccessToken()`: Tạo access token (expires 1h)
   - `generateRefreshToken()`: Tạo refresh token (expires 7 days)
   - `verifyToken()`: Verify signature và expiry
   - Payload: {user_id, role, exp, iat}

3. **PasswordHasher** (Password security)
   - `hashPassword()`: bcrypt with salt rounds
   - `verifyPassword()`: Compare hashed passwords
   - `validatePasswordStrength()`: Min 8 chars, uppercase, lowercase, number, special char

4. **SessionManager** (Session tracking)
   - `createSession()`: Create session on login
   - `updateActivity()`: Update last_activity timestamp
   - `terminateSession()`: Logout, terminate all sessions

5. **EmailService** (Email notifications)
   - Send verification emails
   - Send password reset links
   - SMTP configuration

### 4.1.5. Biểu đồ hoạt động

```mermaid
flowchart TD
    Start([User click Login]) --> EnterCreds[Nhập email & password]
    EnterCreds --> ClickLogin[Click Login button]
    ClickLogin --> ValidateInput{Validate input?}

    ValidateInput -->|Invalid| ShowError[Hiện lỗi validation]
    ShowError --> EnterCreds

    ValidateInput -->|Valid| SendLoginReq[POST /auth/login]
    SendLoginReq --> CheckCreds{Credentials correct?}

    CheckCreds -->|Incorrect| IncrementFail[Increment failed attempts]
    IncrementFail --> CheckLockout{Failed attempts > 5?}
    CheckLockout -->|Yes| LockAccount[Lock account 15 minutes]
    LockAccount --> ShowLockMsg[Show: Account locked]
    ShowLockMsg --> End([Kết thúc])

    CheckLockout -->|No| ShowCredError[Show: Invalid credentials]
    ShowCredError --> EnterCreds

    CheckCreds -->|Correct| CheckStatus{Account active?}
    CheckStatus -->|Inactive/Banned| ShowStatusError[Show: Account inactive]
    ShowStatusError --> End

    CheckStatus -->|Active| GenerateTokens[Generate JWT tokens]
    GenerateTokens --> CreateSession[Create session record]
    CreateSession --> LogLogin[Log login history]
    LogLogin --> SaveTokens[Lưu tokens vào localStorage]

    SaveTokens --> CheckRole{Role?}
    CheckRole -->|Admin| RedirectAdmin[Redirect to Admin Dashboard]
    CheckRole -->|Customer| RedirectChat[Redirect to Chat Interface]

    RedirectAdmin --> End
    RedirectChat --> End
```

### 4.1.6. Biểu đồ tuần tự

```mermaid
sequenceDiagram
    participant User as User Browser
    participant UI as Auth UI Component
    participant API as AuthService API
    participant JWT as JWTManager
    participant DB as Database
    participant Email as EmailService

    Note over User,Email: Registration Flow

    User->>UI: Fill registration form
    User->>UI: Click Register
    UI->>UI: Validate input (client-side)

    UI->>API: POST /auth/register {email, password, ...}
    API->>API: Validate input (server-side)

    alt Email already exists
        API-->>UI: 409 Conflict {message: "Email exists"}
        UI-->>User: Show error message
    else Email unique
        API->>API: Hash password with bcrypt
        API->>DB: INSERT INTO users
        DB-->>API: user_id

        API->>JWT: generateVerificationToken(user_id)
        JWT-->>API: verification_token

        API->>Email: sendVerificationEmail(user, token)
        Email-->>API: Email sent

        API-->>UI: 201 Created {user_id, message}
        UI-->>User: Show success: Check your email
    end

    Note over User,Email: Login Flow

    User->>UI: Enter email & password
    User->>UI: Click Login
    UI->>API: POST /auth/login {email, password}

    API->>DB: SELECT * FROM users WHERE email=?
    DB-->>API: User data

    alt User not found
        API-->>UI: 401 Unauthorized
        UI-->>User: Invalid credentials
    else User found
        API->>API: Verify password hash
        alt Password incorrect
            API->>DB: INSERT INTO login_history (success=FALSE)
            API-->>UI: 401 Unauthorized
            UI-->>User: Invalid credentials
        else Password correct
            API->>JWT: generateAccessToken(user_id, role)
            JWT-->>API: access_token

            API->>JWT: generateRefreshToken(user_id)
            JWT-->>API: refresh_token

            API->>DB: INSERT INTO refresh_tokens
            API->>DB: INSERT INTO user_sessions
            API->>DB: UPDATE users SET last_login
            API->>DB: INSERT INTO login_history (success=TRUE)

            API-->>UI: 200 OK {access_token, refresh_token, user}
            UI->>UI: Store tokens in localStorage
            UI-->>User: Redirect to dashboard/chat
        end
    end
```

---

## CHỨC NĂNG 2: ADMIN DASHBOARD UI

### 4.2.1. Mô tả
Giao diện quản trị cho Admin để quản lý training data, models, documents.

### 4.2.2. Thiết kế giao diện UI

#### UI Layout: Admin Dashboard
```
┌─────────────────────────────────────────────────────────────────────┐
│ PTIT Chatbot Admin              [User: admin]  [Logout]             │
├─────────────┬───────────────────────────────────────────────────────┤
│             │                                                         │
│  Dashboard  │   Dashboard Overview                                   │
│  ───────    │   ┌──────────────┬──────────────┬──────────────┐      │
│             │   │Total Samples │Total Models  │ Conversations│      │
│  Training   │   │    5,420     │      12      │    1,245     │      │
│   - Labels  │   └──────────────┴──────────────┴──────────────┘      │
│   - Samples │                                                         │
│   - QA Pairs│   Training Jobs Status                                 │
│             │   ┌─────────────────────────────────────────────┐      │
│  Models     │   │ Job #42: ptit_classifier_v2                 │      │
│   - List    │   │ Status: Running (65%)                       │      │
│   - Train   │   │ Estimated completion: 7 mins                │      │
│   - Deploy  │   └─────────────────────────────────────────────┘      │
│             │                                                         │
│  Documents  │   Recent Activity                                      │
│   - Upload  │   • Model v1.5 deployed - 2 hours ago                  │
│   - Manage  │   • 145 new samples added - 5 hours ago                │
│   - Sync    │   • Document tuyen_sinh_2025.pdf synced                │
│             │                                                         │
│  Analytics  │   Performance Chart                                    │
│             │   [Line chart showing model accuracy over time]        │
│  Users      │                                                         │
│   - List    │                                                         │
│   - Manage  │                                                         │
│             │                                                         │
└─────────────┴───────────────────────────────────────────────────────┘
```

#### UI: Training Data Management
```
┌─────────────────────────────────────────────────────────────────────┐
│  Training Samples Management                  [+ Add Sample]         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Filter by Label: [All Labels ▼]    Search: [____________] [Search]  │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ ID │ Label        │ Content                    │ Created     │   │
│  ├────┼──────────────┼────────────────────────────┼─────────────┤   │
│  │1052│hoc_phi_cntt  │Học phí CNTT là bao nhiêu?  │2025-01-15   │   │
│  │    │              │                            │ [Edit][Del] │   │
│  ├────┼──────────────┼────────────────────────────┼─────────────┤   │
│  │1051│tuyen_sinh    │Điểm chuẩn CNTT năm nay?    │2025-01-15   │   │
│  │    │              │                            │ [Edit][Del] │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  [< Previous]  Page 1 of 108  [Next >]                               │
│                                                                       │
│  [Bulk Import CSV]  [Export to CSV]                                  │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

#### UI: Model Training
```
┌─────────────────────────────────────────────────────────────────────┐
│  Train New Model                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Model Name:     [ptit_classifier_v3___________________]             │
│                                                                       │
│  Model Type:     [ Classifier ▼ ]                                    │
│                                                                       │
│  Algorithm:      [ Random Forest ▼ ]                                 │
│                                                                       │
│  Hyperparameters:                                                    │
│    - n_estimators:      [100____]                                    │
│    - max_depth:         [10_____]                                    │
│    - min_samples_split: [5______]                                    │
│                                                                       │
│  Training Data:                                                      │
│    [x] All labels                                                    │
│    [ ] Specific labels: [Select labels...]                           │
│                                                                       │
│  Train/Test Split:  [80%] / [20%]                                    │
│                                                                       │
│  Advanced Options:                                                   │
│    [x] Hyperparameter tuning (Grid Search)                           │
│    [ ] K-Fold Cross Validation (k=5)                                 │
│    [x] Auto-deploy if accuracy > 90%                                 │
│                                                                       │
│             [Cancel]        [Start Training]                         │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2.3. Biểu đồ lớp chi tiết

```mermaid
classDiagram
    class AdminDashboard {
        -AuthContext authContext
        -Router router
        +render() Component
        +checkAdminRole() bool
    }

    class TrainingDataView {
        -TrainingDataService service
        -State labels
        -State samples
        -State filters
        +loadLabels() void
        +loadSamples(filters) void
        +createSample(data) void
        +updateSample(id, data) void
        +deleteSample(id) void
        +bulkImport(file) void
        +exportCSV() void
    }

    class ModelManagementView {
        -ModelService service
        -State models
        -State trainingJobs
        +loadModels() void
        +startTraining(config) void
        +checkJobStatus(jobId) void
        +deployModel(modelId) void
        +compareModels(modelIds) void
    }

    class DocumentManagementView {
        -DocumentService service
        -State documents
        +loadDocuments() void
        +uploadDocument(file, metadata) void
        +syncDocument(docId) void
        +deleteDocument(docId) void
    }

    class AnalyticsDashboard {
        -AnalyticsService service
        -State metrics
        -State charts
        +loadMetrics() void
        +loadCharts(dateRange) void
        +exportReport() void
    }

    AdminDashboard --> TrainingDataView
    AdminDashboard --> ModelManagementView
    AdminDashboard --> DocumentManagementView
    AdminDashboard --> AnalyticsDashboard
```

**Giải thích:**

1. **AdminDashboard** (Main layout)
   - Sidebar navigation
   - Header with user info
   - Check admin role via AuthContext
   - Route protection

2. **TrainingDataView** (Training data management)
   - CRUD operations cho labels, samples
   - Filtering, pagination
   - Bulk import/export

3. **ModelManagementView** (Model management)
   - List models với metrics
   - Training job creation & monitoring
   - Model deployment

4. **DocumentManagementView** (Document management)
   - Upload documents
   - View processing status
   - Trigger sync to Server 2

5. **AnalyticsDashboard** (Analytics & reports)
   - Charts: model performance over time
   - Statistics: samples/labels/conversations
   - Export reports

### 4.2.4. Biểu đồ hoạt động

```mermaid
flowchart TD
    Start([Admin login]) --> CheckAuth{Authenticated?}
    CheckAuth -->|No| RedirectLogin[Redirect to login]
    RedirectLogin --> End([Kết thúc])

    CheckAuth -->|Yes| CheckRole{Role = admin?}
    CheckRole -->|No| ShowUnauth[Show: Unauthorized]
    ShowUnauth --> End

    CheckRole -->|Yes| LoadDashboard[Load Admin Dashboard]
    LoadDashboard --> LoadStats[Load statistics]
    LoadStats --> LoadJobs[Load training jobs status]
    LoadJobs --> LoadActivity[Load recent activity]

    LoadActivity --> ShowDashboard[Display dashboard]
    ShowDashboard --> WaitAction[Wait for admin action]

    WaitAction --> SelectAction{Admin action?}

    SelectAction -->|Manage Samples| NavSamples[Navigate to Training Data]
    NavSamples --> LoadSamplesView[Load samples with pagination]
    LoadSamplesView --> WaitSampleAction[Wait for action]

    WaitSampleAction --> SampleAction{Action?}
    SampleAction -->|Add| ShowAddForm[Show add sample form]
    ShowAddForm --> SubmitSample[Submit sample]
    SubmitSample --> ValidateSample{Valid?}
    ValidateSample -->|No| ShowSampleError[Show error]
    ShowSampleError --> ShowAddForm
    ValidateSample -->|Yes| SaveSample[POST /api/v1/samples]
    SaveSample --> RefreshList[Refresh sample list]
    RefreshList --> WaitSampleAction

    SampleAction -->|Edit| ShowEditForm[Show edit form]
    SampleAction -->|Delete| ConfirmDelete{Confirm?}
    ConfirmDelete -->|Yes| DeleteSample[DELETE /api/v1/samples/id]
    DeleteSample --> RefreshList

    SelectAction -->|Train Model| NavTrain[Navigate to Model Training]
    NavTrain --> ShowTrainForm[Show training config form]
    ShowTrainForm --> SubmitTrain[Submit training config]
    SubmitTrain --> ValidateConfig{Valid?}
    ValidateConfig -->|No| ShowConfigError[Show error]
    ShowConfigError --> ShowTrainForm
    ValidateConfig -->|Yes| StartJob[POST /api/v1/models/train]
    StartJob --> PollStatus[Poll job status]
    PollStatus --> ShowProgress[Show progress bar]

    ShowProgress --> CheckComplete{Job complete?}
    CheckComplete -->|No| WaitAndPoll[Wait 5s]
    WaitAndPoll --> PollStatus
    CheckComplete -->|Yes| ShowResult[Show training result]
    ShowResult --> WaitAction

    SelectAction -->|Upload Document| NavDocs[Navigate to Documents]
    SelectAction -->|Logout| Logout[Logout]
    Logout --> End
```

### 4.2.5. Biểu đồ tuần tự

```mermaid
sequenceDiagram
    participant Admin as Admin Browser
    participant UI as Admin Dashboard UI
    participant Auth as AuthService
    participant API1 as Server 1 API
    participant API2 as Server 2 API

    Admin->>UI: Access /admin
    UI->>Auth: Check token in localStorage
    Auth->>Auth: Verify JWT token

    alt Token invalid/expired
        Auth-->>UI: Redirect to /login
    else Token valid
        Auth-->>UI: User data {role: admin}

        alt Role != admin
            UI-->>Admin: Show: Unauthorized
        else Role = admin
            UI->>API1: GET /api/v1/dashboard/stats
            API1-->>UI: Statistics data

            UI->>API1: GET /api/v1/training/jobs?status=running
            API1-->>UI: Running jobs

            UI-->>Admin: Display dashboard

            Note over Admin,UI: Admin clicks "Train Model"

            Admin->>UI: Navigate to Training page
            UI->>API1: GET /api/v1/labels
            API1-->>UI: List of labels

            UI-->>Admin: Show training form

            Admin->>UI: Fill config & Submit
            UI->>API1: POST /api/v1/models/train {config}
            API1->>API1: Queue training job
            API1-->>UI: 202 Accepted {job_id: 42}

            UI-->>Admin: Show: Training job queued

            loop Poll every 5 seconds
                UI->>API1: GET /api/v1/training/jobs/42
                API1-->>UI: {status: running, progress: 65%}
                UI-->>Admin: Update progress bar
            end

            Note over API1: Training completed

            UI->>API1: GET /api/v1/training/jobs/42
            API1-->>UI: {status: completed, metrics: {...}}

            UI-->>Admin: Show: Training completed with metrics

            alt Auto-deploy enabled
                API1->>API2: POST /model/update {model_version}
                API2-->>API1: 200 OK
                UI-->>Admin: Model deployed to production
            end
        end
    end
```

---

## CHỨC NĂNG 3: CUSTOMER CHAT UI

### 4.3.1. Mô tả
Giao diện chat cho người dùng cuối để hỏi đáp với chatbot.

### 4.3.2. Thiết kế giao diện UI

#### UI Layout: Chat Interface
```
┌─────────────────────────────────────────────────────────────────────┐
│  PTIT Chatbot                              [User: nguyenvana] [⚙]   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                                                               │    │
│  │  🤖 Xin chào! Tôi là chatbot tư vấn của PTIT.                │    │
│  │     Bạn muốn hỏi gì?                              10:30 AM   │    │
│  │                                                               │    │
│  │                          Học phí ngành CNTT là bao nhiêu?  👤│    │
│  │                                                   10:31 AM   │    │
│  │                                                               │    │
│  │  🤖 Học phí ngành Công nghệ Thông tin năm 2025 là            │    │
│  │     12.000.000 VNĐ/năm theo quy định tại Quyết định...       │    │
│  │                                                               │    │
│  │     📄 Sources:                                               │    │
│  │     - tuyen_sinh_2025.pdf (page 3)                           │    │
│  │     - hoc_phi_2025.pdf (page 1)                              │    │
│  │                                              10:31 AM        │    │
│  │                                                               │    │
│  │                          Cảm ơn bạn!                       👤│    │
│  │                                                   10:32 AM   │    │
│  │                                                               │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  [Type your message...                                    ] [Send]   │
│                                                                       │
│  Quick actions: [Tuyển sinh] [Học phí] [Chương trình ĐT]            │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

#### UI: Conversation History Sidebar
```
┌─────────────────────────┐
│  Conversations          │
├─────────────────────────┤
│                         │
│  [+ New Chat]           │
│                         │
│  Today                  │
│  • Học phí CNTT         │
│  • Điểm chuẩn 2025      │
│                         │
│  Yesterday              │
│  • Đăng ký học phần     │
│  • Lịch thi cuối kỳ     │
│                         │
│  Last 7 days            │
│  • Thông tin ký túc xá  │
│  • Học bổng sinh viên   │
│                         │
└─────────────────────────┘
```

### 4.3.3. Biểu đồ lớp chi tiết

```mermaid
classDiagram
    class ChatInterface {
        -AuthContext authContext
        -WebSocketClient wsClient
        -State conversations
        -State currentConversation
        -State messages
        +loadConversations() void
        +selectConversation(convId) void
        +createNewConversation() void
        +sendMessage(text) void
        +receiveMessage(message) void
        +loadHistory(convId) void
    }

    class MessageComponent {
        -Message message
        -bool isUser
        +render() Component
        +formatTimestamp(time) String
        +renderSources(sources) Component
    }

    class WebSocketClient {
        -String serverUrl
        -WebSocket socket
        -EventEmitter events
        +connect(token) void
        +disconnect() void
        +sendMessage(data) void
        +onMessage(callback) void
        +onError(callback) void
    }

    class ConversationService {
        -HttpClient http
        +getConversations(userId) List~Conversation~
        +getMessages(convId) List~Message~
        +createConversation() Conversation
        +deleteConversation(convId) bool
    }

    class ChatService {
        -HttpClient http
        +sendQuery(query, convId) ChatResponse
        +streamQuery(query, convId) Stream
        +rateResponse(messageId, rating) bool
    }

    ChatInterface --> MessageComponent
    ChatInterface --> WebSocketClient
    ChatInterface --> ConversationService
    ChatInterface --> ChatService
```

**Giải thích:**

1. **ChatInterface** (Main chat UI)
   - Manage conversations list
   - Send/receive messages
   - WebSocket connection for real-time
   - Load conversation history

2. **MessageComponent** (Message bubble)
   - Render user vs bot messages differently
   - Show sources with links
   - Timestamp formatting
   - Copy message, thumbs up/down

3. **WebSocketClient** (Real-time communication)
   - Connect to Server 2 WebSocket
   - Send typing indicators
   - Receive streaming responses
   - Handle reconnection

4. **ConversationService** (Conversation management)
   - CRUD operations cho conversations
   - Load message history
   - Search conversations

5. **ChatService** (Chat API)
   - Send queries to Server 2
   - Handle streaming responses
   - Rate responses (feedback)

### 4.3.4. Biểu đồ hoạt động

```mermaid
flowchart TD
    Start([User mở chat]) --> CheckAuth{Logged in?}
    CheckAuth -->|No| ShowGuestPrompt[Hiện: Login để lưu lịch sử]
    ShowGuestPrompt --> AllowGuest{Continue as guest?}
    AllowGuest -->|No| RedirectLogin[Redirect to login]
    RedirectLogin --> End([Kết thúc])
    AllowGuest -->|Yes| LoadChat[Load chat interface]

    CheckAuth -->|Yes| LoadConvs[Load conversations]
    LoadConvs --> CheckHasConv{Has conversations?}
    CheckHasConv -->|Yes| LoadLatest[Load latest conversation]
    LoadLatest --> LoadChat
    CheckHasConv -->|No| CreateNew[Create new conversation]
    CreateNew --> LoadChat

    LoadChat --> ShowInterface[Display chat interface]
    ShowInterface --> WaitInput[Wait for user input]

    WaitInput --> UserAction{User action?}

    UserAction -->|Type message| ShowTyping[Show typing indicator]
    ShowTyping --> UserSubmit[User press Send/Enter]
    UserSubmit --> ValidateMsg{Message not empty?}
    ValidateMsg -->|Empty| WaitInput

    ValidateMsg -->|Valid| SendMsg[Send message to Server 2]
    SendMsg --> ShowUserMsg[Display user message bubble]
    ShowUserMsg --> ShowBotTyping[Show bot typing...]

    ShowBotTyping --> WaitResponse[Wait for response from Server 2]
    WaitResponse --> ReceiveResp[Receive response]
    ReceiveResp --> HideBotTyping[Hide bot typing]
    HideBotTyping --> ShowBotMsg[Display bot message bubble]

    ShowBotMsg --> ShowSources{Has sources?}
    ShowSources -->|Yes| RenderSources[Render source links]
    RenderSources --> SaveMsg
    ShowSources -->|No| SaveMsg[Save message to conversation]

    SaveMsg --> WaitInput

    UserAction -->|Select conversation| LoadMsgs[Load messages from selected conv]
    LoadMsgs --> ShowInterface

    UserAction -->|New chat| CreateNewConv[Create new conversation]
    CreateNewConv --> ClearInterface[Clear chat interface]
    ClearInterface --> WaitInput

    UserAction -->|Logout| Logout[Logout]
    Logout --> End
```

### 4.3.5. Biểu đồ tuần tự

```mermaid
sequenceDiagram
    participant User as User Browser
    participant UI as Chat UI
    participant Auth as AuthService
    participant WS as WebSocket
    participant API as Server 2 API

    User->>UI: Open chat page
    UI->>Auth: Check authentication
    Auth-->>UI: User authenticated

    UI->>API: GET /api/v1/conversations?user_id=...
    API-->>UI: List<Conversation>

    alt Has conversations
        UI->>API: GET /api/v1/conversations/{conv_id}/messages
        API-->>UI: List<Message>
        UI-->>User: Display conversation history
    else No conversations
        UI->>API: POST /api/v1/conversations {user_id}
        API-->>UI: new_conversation {conv_id}
    end

    UI->>WS: Connect WebSocket with JWT token
    WS-->>UI: Connection established

    Note over User,API: User sends message

    User->>UI: Type "Học phí CNTT là bao nhiêu?"
    User->>UI: Press Send

    UI->>UI: Display user message bubble
    UI->>WS: Send {query, conversation_id}

    WS->>API: Forward query to RAG handler
    API->>API: Process RAG query

    alt Streaming enabled
        loop Stream response
            API->>WS: Stream chunk
            WS->>UI: Forward chunk
            UI->>UI: Append to bot message
            UI-->>User: Display partial response
        end
    else Non-streaming
        API->>WS: Complete response
        WS->>UI: Forward response
        UI->>UI: Display bot message
        UI-->>User: Show complete response
    end

    UI->>UI: Display sources (if any)
    UI->>API: POST /api/v1/messages {conv_id, role, content, sources}
    API-->>UI: message_id

    Note over User,UI: User rates response

    User->>UI: Click thumbs up
    UI->>API: POST /api/v1/feedback {message_id, rating: 1}
    API-->>UI: 200 OK
    UI-->>User: Show: Thanks for feedback
```

---

## 5. TƯƠNG TÁC VỚI CÁC MODULE KHÁC

### 5.1. Tương tác giữa Client 1 và Server 1

```mermaid
sequenceDiagram
    participant C1 as Client 1 (Admin UI)
    participant S1 as Server 1 (Training Module)

    Note over C1,S1: Training Data Management

    C1->>S1: GET /api/v1/labels
    S1-->>C1: List<Label>

    C1->>S1: POST /api/v1/samples {label_id, content}
    S1-->>C1: 201 Created {sample_id}

    Note over C1,S1: Model Training

    C1->>S1: POST /api/v1/models/train {config}
    S1-->>C1: 202 Accepted {job_id}

    loop Poll job status
        C1->>S1: GET /api/v1/training/jobs/{job_id}
        S1-->>C1: {status, progress, logs}
    end

    Note over C1,S1: Document Upload

    C1->>S1: POST /api/v1/documents/upload (multipart)
    S1-->>C1: 202 Accepted {doc_id}

    C1->>S1: POST /api/v1/documents/{doc_id}/sync
    S1-->>C1: 200 OK {synced: true}
```

### 5.2. Tương tác giữa Client 2 và Server 2

```mermaid
sequenceDiagram
    participant C2 as Client 2 (Customer UI)
    participant Auth as Auth Service
    participant S2 as Server 2 (RAG Module)

    C2->>Auth: POST /auth/login {email, password}
    Auth-->>C2: {access_token, refresh_token}

    C2->>S2: POST /api/v1/chat/query (with JWT)
    S2->>Auth: Verify token
    Auth-->>S2: User validated

    S2->>S2: Process RAG query
    S2-->>C2: {answer, sources, confidence}

    Note over C2: Token expired

    C2->>Auth: POST /auth/refresh {refresh_token}
    Auth-->>C2: {new_access_token}

    C2->>S2: Continue using new token
```

### 5.3. Biểu đồ triển khai tổng thể

```mermaid
graph TB
    subgraph "Frontend - Client Side"
        C1[Admin Dashboard<br/>React/Vue]
        C2[Customer Chat UI<br/>React/Vue]
    end

    subgraph "Backend - Auth Service"
        Auth[Auth API<br/>Flask/FastAPI]
        DB2[(User Database<br/>PostgreSQL)]
        Redis2[(Session Store<br/>Redis)]

        Auth --> DB2
        Auth --> Redis2
    end

    subgraph "Backend - Server 1"
        S1[Training API]
        DB1[(Training Data<br/>PostgreSQL)]
    end

    subgraph "Backend - Server 2"
        S2[RAG API]
        VDB[(Vector DB<br/>ChromaDB)]
    end

    C1 -->|HTTP/REST| S1
    C1 -->|HTTP/REST| Auth

    C2 -->|HTTP/REST| Auth
    C2 -->|WebSocket| S2
    C2 -->|HTTP/REST| S2

    S2 -.->|Verify token| Auth
    S1 -.->|Sync docs| S2

    style C1 fill:#87CEEB
    style C2 fill:#87CEEB
    style Auth fill:#90EE90
    style DB2 fill:#90EE90
    style Redis2 fill:#90EE90
```

---

## 6. BẢO MẬT & TỐI ƯU HÓA

### 6.1. Bảo mật

1. **Authentication:**
   - JWT với short-lived access tokens (1h)
   - Refresh tokens với longer expiry (7 days)
   - Token blacklist khi logout
   - HTTPS only

2. **Authorization:**
   - Role-based access control (Admin vs Customer)
   - Route guards trên frontend
   - API endpoint authorization

3. **Password Security:**
   - bcrypt hashing với salt
   - Password strength validation
   - Rate limiting cho login attempts
   - Account lockout sau 5 failed attempts

4. **XSS & CSRF Protection:**
   - Input sanitization
   - Output encoding
   - CSRF tokens cho state-changing operations
   - Content Security Policy headers

### 6.2. Tối ưu hóa Performance

1. **Frontend:**
   - Code splitting
   - Lazy loading components
   - Image optimization
   - Caching với localStorage/sessionStorage
   - Debounce/throttle cho search inputs

2. **API Calls:**
   - Request batching
   - Response caching
   - Pagination cho large lists
   - WebSocket cho real-time updates

3. **UI/UX:**
   - Loading skeletons
   - Optimistic UI updates
   - Infinite scroll
   - Progressive image loading

---

## 7. KẾT LUẬN

### 7.1. Tổng kết
Module 3 (UI & Authentication) cung cấp giao diện và bảo mật cho hệ thống:
- **Admin UI**: Quản lý toàn bộ training data, models, documents
- **Customer UI**: Chat interface với real-time responses
- **Auth Service**: JWT-based authentication, RBAC

Thiết kế tập trung vào:
- **Security**: JWT tokens, password hashing, RBAC
- **UX**: Responsive design, real-time updates, intuitive navigation
- **Performance**: Code splitting, caching, WebSocket

### 7.2. Công việc tiếp theo
1. Implement authentication service (JWT)
2. Build Admin Dashboard UI (React/Vue)
3. Build Customer Chat UI với WebSocket
4. Responsive design cho mobile
5. Integration testing với Server 1 & Server 2

---

**Ngày hoàn thành:** [Ngày/Tháng/Năm]
**Chữ ký:** _______________
