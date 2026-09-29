# Kubernetes bindings to the observed table (subphase 1.14a).
#
# Produce the input with:
#   kubectl get rolebindings,clusterrolebindings -A -o json > bindings.json
# and run:
#   jq -r --arg cluster NAME -f recipes/kubernetes.jq bindings.json > observed.csv
#
# One row per subject per binding. A ServiceAccount is a service, a
# Group is a group the cluster cannot list the members of, and a User
# is a name the authenticator asserts, so its kind stays unknown. A
# RoleBinding to a ClusterRole is a grant of that cluster role inside
# the binding's namespace, so the role reference carries the namespace
# only for a Role.
["provider","account","identity_id","identity_name","identity_type","identity_kind",
 "role","role_name","mode","path"],
(.items[]
  | . as $binding
  | .subjects[]?
  | [
      "kubernetes",
      $cluster,
      (if .kind == "ServiceAccount" then "serviceaccount:" + .namespace + "/" + .name
       elif .kind == "Group" then "group:" + .name
       else "user:" + .name end),
      .name,
      (.kind | ascii_downcase),
      (if .kind == "ServiceAccount" then "service"
       elif .kind == "Group" then "group"
       else "unknown" end),
      (($binding.roleRef.kind | ascii_downcase) + ":"
       + (if $binding.roleRef.kind == "Role" then $binding.metadata.namespace + "/" else "" end)
       + $binding.roleRef.name),
      $binding.roleRef.name,
      "standing",
      ""
    ])
| @csv
