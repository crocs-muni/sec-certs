from flask_principal import Permission, RoleNeed

admin_permission = Permission(RoleNeed("admin"))

chat_permission = Permission(RoleNeed("chat"), RoleNeed("admin"))
