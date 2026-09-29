# A Google Cloud project's policy to the observed table (subphase 1.14a).
#
# Produce the input with:
#   gcloud projects get-iam-policy PROJECT_ID --format=json > policy.json
# and run:
#   jq -r --arg project PROJECT_ID -f recipes/google-cloud.jq policy.json > observed.csv
#
# One row per member per binding. The member's prefix is its type:
# user, serviceAccount, group, domain, or one of the two public forms
# (allUsers, allAuthenticatedUsers), which are recorded as external so
# a public grant shows as a guest holding a role rather than vanishing.
# A binding with a condition is still a grant; the condition is not
# read here, which the native parser in 1.14c is for.
["provider","account","identity_id","identity_name","identity_type","identity_kind",
 "role","role_name","mode","path"],
(.bindings[]
  | . as $binding
  | .members[]
  | . as $text
  | (split(":")) as $parts
  | {type: $parts[0], name: ($parts[1] // $text)} as $member
  | [
      "gcp",
      $project,
      $text,
      $member.name,
      $member.type,
      (if $member.type == "serviceAccount" then "service"
       elif $member.type == "user" then "person"
       elif $member.type == "group" then "group"
       else "external" end),
      $binding.role,
      $binding.role,
      "standing",
      ""
    ])
| @csv
