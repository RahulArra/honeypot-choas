from core.filesystem.virtual_fs import VirtualFileSystem
from core.engine.rule_engine import RuleEngine
from core.parser.input_parser import normalize_input, sanitize_input
from core.parser.command_classifier import classify_command


def run_test(commands):

    vfs = VirtualFileSystem()
    engine = RuleEngine(vfs)

    for command in commands:

        command = normalize_input(command)
        command = sanitize_input(command)

        category = classify_command(command)

        print(f"\nCommand: {command}")
        print(f"Category: {category}")

        output = engine.execute(command)

        print("Output:")
        print(output)


if __name__ == "__main__":

    commands = [
        "ls",
        "pwd",
        "mkdir test",
        "cd test",
        "pwd",
        "touch file1.txt",
        "ls",
        "cat file1.txt",
        "rm file1.txt",
        "ls",
        "wget http://malware.com",
        "sudo su",
        "lss"
    ]

    run_test(commands)