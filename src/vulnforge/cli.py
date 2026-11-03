from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from vulnforge.config import load_yaml

PROJECTS_FILE = Path("config/projects.yaml")

VALID_FIELDS = {"path", "description", "revision", "build_command", "language"}


def load_projects() -> dict:
    if not PROJECTS_FILE.is_file():
        return {"projects": {}}
    return load_yaml(PROJECTS_FILE)


def save_projects(data: dict) -> None:
    PROJECTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PROJECTS_FILE.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def cmd_add(args: argparse.Namespace) -> None:
    if not "/" not in args.project:
        print("Error: project ID cannot contain '/'", file=sys.stderr)
        sys.exit(1)
    if not args.path or not Path(args.path).expanduser().resolve().is_dir():
        print(f"Error: path is not a directory: {args.path}", file=sys.stderr)
        sys.exit(1)
    data = load_projects()
    projects = data.setdefault("projects", {})
    if args.project in projects:
        print(f"Error: project already exists: {args.project}", file=sys.stderr)
        sys.exit(1)
    projects[args.project] = {
        "path": str(Path(args.path).expanduser().resolve()),
        "description": args.description or "",
        "revision": args.revision or "",
    }
    save_projects(data)
    print(f"Added project: {args.project}")


def cmd_remove(args: argparse.Namespace) -> None:
    data = load_projects()
    projects = data.setdefault("projects", {})
    if args.project not in projects:
        print(f"Error: project not found: {args.project}", file=sys.stderr)
        sys.exit(1)
    del projects[args.project]
    save_projects(data)
    print(f"Removed project: {args.project}")


def cmd_list(_args: argparse.Namespace) -> None:
    data = load_projects()
    projects = data.get("projects", {})
    if not projects:
        print("No projects registered.")
        return
    for name, cfg in sorted(projects.items()):
        desc = cfg.get("description", "")
        print(f"  {name}: {cfg.get('path', '')}  {desc}")


def cmd_update(args: argparse.Namespace) -> None:
    data = load_projects()
    projects = data.setdefault("projects", {})
    if args.project not in projects:
        print(f"Error: project not found: {args.project}", file=sys.stderr)
        sys.exit(1)
    entry = projects[args.project]
    if args.path:
        if not Path(args.path).expanduser().resolve().is_dir():
            print(f"Error: path is not a directory: {args.path}", file=sys.stderr)
            sys.exit(1)
        entry["path"] = str(Path(args.path).expanduser().resolve())
    if args.description is not None:
        entry["description"] = args.description
    if args.revision is not None:
        entry["revision"] = args.revision
    if args.build_command is not None:
        entry["build_command"] = args.build_command
    if args.language is not None:
        entry["language"] = args.language
    save_projects(data)
    print(f"Updated project: {args.project}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="vulnforge", description="Manage VulnForge project registrations")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Register a project")
    p_add.add_argument("project")
    p_add.add_argument("path")
    p_add.add_argument("--description", default="")
    p_add.add_argument("--revision", default="")
    p_add.set_defaults(func=cmd_add)

    p_remove = sub.add_parser("remove", help="Remove a project")
    p_remove.add_argument("project")
    p_remove.set_defaults(func=cmd_remove)

    p_list = sub.add_parser("list", help="List registered projects")
    p_list.set_defaults(func=cmd_list)

    p_update = sub.add_parser("update", help="Update a project")
    p_update.add_argument("project")
    p_update.add_argument("--path")
    p_update.add_argument("--description")
    p_update.add_argument("--revision")
    p_update.add_argument("--build-command", dest="build_command")
    p_update.add_argument("--language")
    p_update.set_defaults(func=cmd_update)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
