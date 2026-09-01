# TerraSecure Production Model v1.0.0

- **Version:** 1.0.0
- **Build Date:** 2026-09-01T13:03:45.362812
- **Model Type:** XGBoost
- **Training Samples:** 265
- **Features:** 50

- **Accuracy:** 98.11%
- **Precision:** 100.00%
- **Recall:** 96.00%
- **F1-Score:** 0.9796

- **False Positive Rate:** 0.00% (Target: <10%)
- **False Negative Rate:** 4.00% (Target: <5%)

 PASSED
1. default_sg_in_use (0.1015)
2. s3_encryption_disabled (0.1013)
3. lambda_env_vars_unencrypted (0.0756)
4. ecs_task_privilege_escalation (0.0607)
5. api_gateway_no_waf (0.0601)
6. s3_public_acl (0.0494)
7. s3_block_public_access_disabled (0.0488)
8. backup_vault_unencrypted (0.0478)
9. mfa_not_enabled (0.0471)
10. rds_publicly_accessible (0.0397)
