from flask_principal import Permission, RoleNeed

admin_permission = Permission(RoleNeed("admin"))
