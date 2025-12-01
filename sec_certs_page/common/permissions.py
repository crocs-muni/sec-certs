from flask_principal import Permission, RoleNeed

admin_permission = Permission(RoleNeed("admin"))

chat_permission = Permission(RoleNeed("chat"), RoleNeed("admin"))

dashboard_permission = Permission(RoleNeed("dashboard"), RoleNeed("admin"))
