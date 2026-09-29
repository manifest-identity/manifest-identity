# Okta administrator roles to the observed table (subphase 1.14a).
#
# Okta has no single export; the input is assembled from two reads,
# both paged by the cursor in the Link header:
#   GET /api/v1/iam/assignees/users        every user holding a role
#   GET /api/v1/users/{id}/roles           that user's roles
# assembled as a JSON array of {"user": <user object>, "roles": [<role>...]}
# and run:
#   jq -r --arg org ORG_SUBDOMAIN -f recipes/okta.jq admins.json > observed.csv
#
# One row per role per user. The role's type is the definition (the
# labels vary by locale, the types do not). A role that arrives
# through a group says so in its assignmentType, and the path records
# the hop without the group's name, which this read does not carry;
# the native parser in 1.14e does.
["provider","account","identity_id","identity_name","identity_type","identity_kind",
 "role","role_name","mode","path"],
(.[]
  | . as $entry
  | .roles[]
  | [
      "okta",
      $org,
      $entry.user.id,
      $entry.user.profile.login,
      "user",
      "person",
      .type,
      .label,
      "standing",
      (if .assignmentType == "GROUP" then "membership:group" else "" end)
    ])
| @csv
