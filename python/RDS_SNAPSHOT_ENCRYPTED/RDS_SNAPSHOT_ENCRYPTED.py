# Copyright 2017-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
"""""
#####################################
##           Gherkin               ##
#####################################

Rule Name:
  RDS_SNAPSHOT_ENCRYPTED

Description:
  Check whether Amazon RDS DB Snapshots for the Amazon RDS DB Instances are encrypted. The rule is NON_COMPLIANT, if the DB Snapshot is not encrypted.

Rationale:
  Encrypting a  Amazon RDS DB Snapshot with AWS Key Management Service(KMS) keys ensures protection.

Indicative Severity:
  Medium

Trigger:
  Configuration Change on AWS::RDS::DBSnapshot or AWS::RDS::DBClusterSnapshot

Reports on:
  AWS::RDS::DBSnapshot or AWS::RDS::DBClusterSnapshot

Rule Parameters:
  kmsKeyId(Optional) : AWS KMS key id used for encryption


Scenarios:
  Scenario: 1
    Given: Amazon RDS DB Snapshot available and is encrypted with AWS KMS
    And: parameter 'kmsKeyId' is not provided
    Then: Return COMPLIANT
  Scenario: 2
    Given: Amazon RDS DB Snapshot available and is not encrypted with AWS KMS
    Then: Return NON_COMPLIANT
  Scenario: 3
    Given: Amazon RDS DB Snapshot available and is encrypted with AWS KMS
    And: parameter 'kmsKeyId' is provided
    And: parameter 'kmsKeyId' matched with 'kmsKeyId' in configuration item
    Then: Return COMPLIANT
  Scenario: 4
    Given: Amazon RDS DB Snapshot available and is encrypted with AWS KMS
    And: parameter 'kmsKeyId' is provided
    And: parameter 'kmsKeyId' not matched with 'kmsKeyId' in configuration item
    Then: Return NON_COMPLIANT

same scenarios for DB clusters
"""""

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType


class RDS_SNAPSHOT_ENCRYPTED(ConfigRule):

    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        encryption_enabled = configuration_item['configuration'].get('encrypted')
        if encryption_enabled:
            if valid_rule_parameters and valid_rule_parameters.get("kmsKeyId"):
                rds_kms_keyid = configuration_item['configuration'].get('kmsKeyId')
                if rds_kms_keyid and rds_kms_keyid == valid_rule_parameters.get("kmsKeyId"):
                    return [Evaluation(ComplianceType.COMPLIANT)]
                return [Evaluation(ComplianceType.NON_COMPLIANT,
                                   annotation="RDS snapshot encrypted KMS key id"
                                              " does not match with configured KMS key id")]
            return [Evaluation(ComplianceType.COMPLIANT)]
        return [Evaluation(ComplianceType.NON_COMPLIANT, annotation="Encryption is not enabled for this DB snapshot")]


def lambda_handler(event, context):
    my_rule = RDS_SNAPSHOT_ENCRYPTED()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
