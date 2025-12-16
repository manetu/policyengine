package authz

#allow = -1 or 1 decision made, no more policy processing
#         0 proceed to phase 2
#
#policy filters for allow==1 or -1 and lets everything else to be passed through
#for further processing
#  1 - public ops, graphql,
#      admin not performing prohibted ops (this for preventing lockout)
# -1 - user ops and operator ops not with corresponding roles
default allow = 0

#------------ jwt checks ---------------
jwt_ok {
	input.principal != {}
}

#<<<<<<<<<<<<<< Rules >>>>>>>>>>>>>>>>>>>>>>

#------------ not allowed ----------------
allow = -1 {
    not jwt_ok
}
