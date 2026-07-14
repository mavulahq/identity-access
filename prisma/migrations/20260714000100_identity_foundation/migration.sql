CREATE TABLE "institutions" (
  "id" TEXT PRIMARY KEY,
  "tenantId" TEXT NOT NULL UNIQUE,
  "legalName" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'ACTIVE',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE "branches" (
  "id" TEXT PRIMARY KEY,
  "institutionId" TEXT NOT NULL REFERENCES "institutions"("id") ON DELETE CASCADE,
  "name" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'ACTIVE',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE ("institutionId", "name")
);
CREATE INDEX "branches_institutionId_idx" ON "branches"("institutionId");
CREATE TABLE "operators" (
  "id" TEXT PRIMARY KEY,
  "email" TEXT NOT NULL UNIQUE,
  "displayName" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'ACTIVE',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE "operator_credentials" (
  "operatorId" TEXT PRIMARY KEY REFERENCES "operators"("id") ON DELETE CASCADE,
  "passwordHash" TEXT NOT NULL,
  "passwordChangedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE "memberships" (
  "id" TEXT PRIMARY KEY,
  "operatorId" TEXT NOT NULL REFERENCES "operators"("id") ON DELETE CASCADE,
  "institutionId" TEXT NOT NULL REFERENCES "institutions"("id") ON DELETE CASCADE,
  "branchId" TEXT REFERENCES "branches"("id") ON DELETE SET NULL,
  "status" TEXT NOT NULL DEFAULT 'ACTIVE',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX "memberships_operator_institution_branch_key" ON "memberships"("operatorId", "institutionId", "branchId");
CREATE INDEX "memberships_institutionId_idx" ON "memberships"("institutionId");
CREATE TABLE "role_assignments" (
  "id" TEXT PRIMARY KEY,
  "membershipId" TEXT NOT NULL REFERENCES "memberships"("id") ON DELETE CASCADE,
  "role" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE ("membershipId", "role")
);
CREATE TABLE "oauth_clients" (
  "id" TEXT PRIMARY KEY,
  "name" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'ACTIVE',
  "redirectUris" JSONB NOT NULL,
  "grantTypes" JSONB NOT NULL,
  "responseTypes" JSONB NOT NULL,
  "tokenEndpointAuthMethod" TEXT NOT NULL,
  "jwks" JSONB,
  "tenantBindings" JSONB NOT NULL,
  "permissions" JSONB NOT NULL,
  "resourceAudiences" JSONB NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE "oidc_artifacts" (
  "model" TEXT NOT NULL,
  "id" TEXT NOT NULL,
  "payload" JSONB NOT NULL,
  "grantId" TEXT,
  "userCode" TEXT,
  "uid" TEXT,
  "expiresAt" TIMESTAMP(3),
  "consumedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY ("model", "id")
);
CREATE INDEX "oidc_artifacts_grantId_idx" ON "oidc_artifacts"("grantId");
CREATE INDEX "oidc_artifacts_userCode_idx" ON "oidc_artifacts"("userCode");
CREATE INDEX "oidc_artifacts_uid_idx" ON "oidc_artifacts"("uid");
CREATE INDEX "oidc_artifacts_expiresAt_idx" ON "oidc_artifacts"("expiresAt");
CREATE TABLE "identity_audit_events" (
  "id" TEXT PRIMARY KEY,
  "action" TEXT NOT NULL,
  "result" TEXT NOT NULL,
  "operatorId" TEXT,
  "clientId" TEXT,
  "institutionId" TEXT,
  "tenantId" TEXT,
  "correlationId" TEXT,
  "metadata" JSONB NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "identity_audit_events_institution_created_idx" ON "identity_audit_events"("institutionId", "createdAt");
CREATE INDEX "identity_audit_events_operator_created_idx" ON "identity_audit_events"("operatorId", "createdAt");
