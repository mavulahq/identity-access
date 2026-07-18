CREATE UNIQUE INDEX memberships_operator_institution_branchless_key
  ON "memberships"("operatorId", "institutionId")
  WHERE "branchId" IS NULL;
