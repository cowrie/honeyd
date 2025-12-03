#!/usr/bin/env python3
# ABOUTME: Precompiles HTML templates to .tmplc files for honeyd webserver
# ABOUTME: Run during build to avoid runtime write permission requirements

import os
import sys

# Add parent directory to path to import htmltmpl
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from htmltmpl import TemplateManager

def precompile_templates(htdocs_dir):
    """Precompile all .tmpl files in the templates directory."""
    templates_dir = os.path.join(htdocs_dir, "templates")

    if not os.path.isdir(templates_dir):
        print(f"Templates directory not found: {templates_dir}", file=sys.stderr)
        return 1

    mgr = TemplateManager(precompile=True)

    # Only compile top-level templates - they will pull in includes
    count = 0
    errors = 0
    for filename in os.listdir(templates_dir):
        if filename.endswith(".tmpl"):
            filepath = os.path.join(templates_dir, filename)
            try:
                # Loading the template will trigger precompilation
                mgr.prepare(filepath)
                print(f"Precompiled: {filepath}")
                count += 1
            except Exception as e:
                print(f"Warning: Could not precompile {filepath}: {e}", file=sys.stderr)
                errors += 1

    print(f"Precompiled {count} templates ({errors} errors)")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <htdocs_dir>", file=sys.stderr)
        sys.exit(1)

    sys.exit(precompile_templates(sys.argv[1]))
