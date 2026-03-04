import json
import posixpath
import copy
import os


class VirtualFileSystem:

    def __init__(self):
        base_path = os.path.join(
            os.path.dirname(__file__),
            "base_fs.json"
        )

        with open(base_path, "r", encoding="utf-8") as f:
            self.fs = copy.deepcopy(json.load(f))

        self.cwd = "/home/root"

    def get_prompt_path(self):
        return self.cwd.replace("/home/root", "~")

    def list_dir(self):
        files = self.fs.get(self.cwd, [])
        return "\n".join(files)
    def pwd(self):
        return self.cwd

    def cd(self, path):
        if path == "..":
            if self.cwd != "/":
                self.cwd = posixpath.dirname(self.cwd)
            return ""

        if path.startswith("/"):
            new_path = path
        else:
            new_path = posixpath.join(self.cwd, path)

        new_path = posixpath.normpath(new_path)

        if new_path in self.fs:
            self.cwd = new_path
            return ""
        else:
            return f"bash: cd: {path}: No such file or directory"

    def mkdir(self, name):
        new_path = posixpath.join(self.cwd, name)
        new_path = posixpath.normpath(new_path)

        if new_path in self.fs:
            return f"mkdir: cannot create directory '{name}': File exists"

        self.fs[new_path] = []
        self.fs[self.cwd].append(name)
        return ""

    def touch(self, name):
        if name not in self.fs[self.cwd]:
            self.fs[self.cwd].append(name)
        return ""

    def rm(self, name):
        if name in self.fs[self.cwd]:
            self.fs[self.cwd].remove(name)
            return ""
        return f"rm: cannot remove '{name}': No such file"

    def cat(self, name):
        if name in self.fs[self.cwd]:
            return f"Simulated content of {name}"
        return f"cat: {name}: No such file"