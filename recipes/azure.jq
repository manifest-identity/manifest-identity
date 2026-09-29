# Azure role assignments to the observed table (subphase 1.14a).
#
# Produce the input for ONE subscription with:
#   az role assignment list --all --include-inherited \
#       --scope /subscriptions/SUBSCRIPTION_ID -o json > assignments.json
# and run:
#   jq -r -f recipes/azure.jq assignments.json > observed.csv
#
# One row per assignment. The account is the subscription read from
# each assignment's scope, and the door refuses a file that names more
# than one subscription, so run the command once per subscription. An
# assignment at a resource group or a resource is recorded at the
# subscription in this table; the native parser in 1.14d keeps the
# finer scope. Entra directory roles and PIM eligibilities are not in
# this command's output and wait for 1.14d as well.
["provider","account","identity_id","identity_name","identity_type","identity_kind",
 "role","role_name","mode","path"],
(.[]
  | [
      "azure",
      ((.scope | capture("^/subscriptions/(?<id>[^/]+)") | .id) // .scope),
      .principalId,
      (.principalName // .principalId),
      (.principalType | ascii_downcase),
      (if .principalType == "User" then "person"
       elif .principalType == "ServicePrincipal" then "service"
       elif .principalType == "Group" then "group"
       else "external" end),
      .roleDefinitionId,
      .roleDefinitionName,
      "standing",
      ""
    ])
| @csv
