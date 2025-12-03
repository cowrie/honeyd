import support
from htmltmpl import TemplateManager, TemplateProcessor

request.send_response(200)
request.send_header("Content-Type", "text/html")
request.send_nocache()
request.end_headers()

# Compile or load already precompiled template.
template = TemplateManager().prepare(request.root + "/templates/index.tmpl")
tproc = TemplateProcessor(0)

# Process commands given to us
message = support.parse_query(request.query)

# Set the title.
tproc.set("title", "Honeyd Administration Interface")

# Visitor counter (persisted in globals)
if 'counter' not in globals():
    counter = 0
counter += 1

greeting = (
    "Welcome to the Honeyd Administration Interface.You are visitor %d.<p>"
) % counter

content = support.interface_table()
content += "<p>" + support.stats_table(request.root) + "</p>\n"
content += "<p>" + support.status_connections(request.root, "tcp") + "</p>\n"
content += "<p>" + support.status_connections(request.root, "udp") + "</p>\n"

side_content = (
    "<div class=graphs>"
    "<img height=155 width=484 src=/graphs/traffic_hourly.gif><br>"
    "<img height=155 width=484 src=/graphs/traffic_daily.gif>"
    "</div>"
)

if message:
    tproc.set("message", message)

tproc.set("greeting", greeting)
tproc.set("content", content)
tproc.set("side_content", side_content)
tproc.set("uptime", support.uptime())

# Print the processed template.
request.wfile.write(tproc.process(template).encode('utf-8'))
