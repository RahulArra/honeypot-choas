from core.filesystem.virtual_fs import VirtualFileSystem


class RuleEngine:

    def __init__(self, vfs: VirtualFileSystem):
        self.vfs = vfs

        self.command_registry = {
            "ls": self.handle_ls,
            "pwd": self.handle_pwd,
            "cd": self.handle_cd,
            "mkdir": self.handle_mkdir,
            "touch": self.handle_touch,
            "rm": self.handle_rm,
            "cat": self.handle_cat,
        }

    def execute(self, command):

        if not command:
            return ""

        parts = command.split()
        cmd = parts[0]
        args = parts[1:]

        if cmd in self.command_registry:
            return self.command_registry[cmd](args)

        return f"bash: {cmd}: command not found"

    # ---- command handlers ----

    def handle_ls(self, args):
        return self.vfs.list_dir()

    def handle_pwd(self, args):
        return self.vfs.pwd()

    def handle_cd(self, args):

        if not args:
            return "bash: cd: missing operand"

        return self.vfs.cd(args[0])

    def handle_mkdir(self, args):

        if not args:
            return "mkdir: missing operand"

        return self.vfs.mkdir(args[0])

    def handle_touch(self, args):

        if not args:
            return "touch: missing file operand"

        return self.vfs.touch(args[0])

    def handle_rm(self, args):

        if not args:
            return "rm: missing operand"

        return self.vfs.rm(args[0])

    def handle_cat(self, args):

        if not args:
            return "cat: missing operand"

        return self.vfs.cat(args[0])