import support
from htmltmpl import TemplateManager, TemplateProcessor

request.send_response(200)
request.send_header("Content-Type", "text/html")
request.send_nocache()
request.end_headers()

# Process commands given to us
message = support.parse_query(request.query)

# Compile or load already precompiled template.
template = TemplateManager().prepare(request.root + "/templates/index.tmpl")
tproc = TemplateProcessor(0)

# Set the title.
tproc.set("title", "Honeyd Configuration Interface")

content = "Welcome to the Honeyd Configuration Interface.<p>"
content += support.config_table()
content += "<p>"
content += support.config_ips(request.root)

if message:
    tproc.set("message", message)
tproc.set("content", content)
tproc.set("uptime", support.uptime())

# Print the processed template.
request.wfile.write(tproc.process(template).encode('utf-8'))
