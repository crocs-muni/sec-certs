'use strict';

function color(highlighted, statuses, d) {
    if (highlighted && highlighted.includes(d.id)) {
        return "#0d6efd"
    } else if (d.status in statuses) {
        return statuses[d.status]["color"];
    } else {
        return "#6c757d";
    }
}

function drag(simulation) {
    function dragstarted(event) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
    }

    function dragged(event, d) {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
    }

    function dragended(event) {
        if (!event.active) simulation.alphaTarget(0);
        event.subject.fx = null;
        event.subject.fy = null;
    }

    return d3.drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended);
}


class CertificateNetwork {
    constructor(data, categories, statuses, refTypes) {
        this.originalData = data;
        this.data = data;
        this.categories = categories;
        this.categoryIds = _.map(this.categories, "id");
        this.statuses = statuses;
        this.refTypes = refTypes;

        this.nodeGroup = null;
        this.linkGroup = null;
        this.simulation = null;
        this.numNodes = null;
        this.numLinks = null;
        this.rendered = false;

        this.filter = {
            status: "any",
            categories: new Set(this.categoryIds),
            onlyRefd: false,
            refTypes: new Set(_.keys(this.refTypes))
        }
    }


    render(element_id, width, height) {
        const element = d3.select("#" + element_id);
        const colorFunc = _.partial(color, this.data.highlighted, this.statuses);

        this.simulation = d3.forceSimulation(this.data.nodes)
            .force("link", d3.forceLink(this.data.links).id(d => d.id).distance(30).strength(1))
            .force("charge", d3.forceManyBody().strength(-100).theta(0.99))
            .force("x", d3.forceX(width / 2))
            .force("y", d3.forceY(height / 2));

        const svg = d3.create("svg")
            .attr("viewBox", [0, 0, width, height])
            .style("font", "12px");

        const defs = svg.append("defs");

        defs.selectAll("marker")
            .data(["default"])
            .join("marker")
            .attr("id", d => d)
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 25)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("fill", "#888")
            .attr("fill-opacity", 0.6)
            .attr("d", "M0,-5L10,0L0,5");

        const categories = Object.keys(this.categories).map(category => this.categories[category]);

        defs.selectAll("g")
            .data(categories)
            .join("g")
            .attr("id", d => d.id)
            .attr("viewBox", "0 0 512 512")
            .attr("transform", "translate(-12, -10) scale(0.05)")
            .html(d => d.svg);

        const g = svg.append("g");

        this.numNodes = svg.append("text")
            .attr("fill", "#000")
            .attr("x", 5)
            .attr("y", 15)
            .text("Nodes: " + this.data.nodes.length);

        this.numLinks = svg.append("text")
            .attr("fill", "#000")
            .attr("x", 5)
            .attr("y", 30)
            .text("Edges: " + this.data.links.length);

        this.linkGroup = g.append("g")
            .attr("stroke", "#888")
            .attr("stroke-opacity", 0.6).selectAll("line");

        this.nodeGroup = g.append("g").selectAll("g");

        this.simulation.on("tick", () => {
            this.linkGroup
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            this.nodeGroup
                .attr("transform", d => d3.zoomIdentity.translate(d.x, d.y));
        });

        function zoomed({transform}) {
            g.attr("transform", transform);
        }

        const zoom = d3.zoom().extent([[0, 0], [width, height]]).scaleExtent([0.125, 4]).on("zoom", zoomed);

        let closest = null;

        svg.on("mousemove", event => {
            let transform = d3.zoomTransform(g.node());
            let ptr = d3.pointer(event, svg.node());
            ptr = transform.invert(ptr);
            let x = ptr[0];
            let y = ptr[1];
            let newClosest = this.simulation.find(x, y);
            if (newClosest !== closest) {
                this.nodeGroup.each(function (d, i) {
                    if (i === newClosest.index) {
                        d3.select(this).select("text").attr("visibility", null);
                        d3.select(this).select("use").attr("fill", "#000");
                    } else if (closest !== null && i === closest.index) {
                        d3.select(this).select("text").attr("visibility", "hidden");
                        d3.select(this).select("use").attr("fill", colorFunc);
                    }
                });
                closest = newClosest;
            }
        });

        svg.call(zoom).call(zoom.transform, d3.zoomIdentity);
        this.update();

        element.append(() => svg.node());

        const statusBox = d3.create("div")
            .classed("mx-3 my-3", true);

        statusBox.append("h4")
            .text("Status");

        const statusFilter = statusBox.append("select")
            .attr("name", "status");

        for (let status in this.statuses) {
            statusFilter.append("option")
                .attr("value", status)
                .text(this.statuses[status]["desc"]);
        }
        statusFilter.append("option")
            .attr("value", "any")
            .property("selected", true)
            .text("Any");

        statusFilter.on("change", event => {
            this.filter.status = event.target.value;
        });

        element.append(() => statusBox.node());

        const referenceBox = d3.create("div")
            .classed("mx-3 my-3", true);

        referenceBox.append("h4")
            .text("References")

        const referenceFilter = referenceBox.append("div").classed("row", true).append("div").classed("col", true);

        const referenceOnly = referenceFilter.append("div")
            .classed("form-check", true)
            .append("span");
        referenceOnly.append("input")
            .attr("type", "checkbox")
            .attr("id", "reference-only")
            .classed("form-check-input", true)
            .property("checked", false);
        referenceOnly.append("label")
            .attr("for", "reference-only")
            .classed("form-check-label", true)
            .text("Only nodes with references");

        referenceOnly.selectAll("#reference-only").on("change", event => {
            this.filter.onlyRefd = event.target.checked;
        });

        for (const [type, value] of Object.entries(this.refTypes)) {
            let elem = referenceFilter.append("div")
                .classed("form-check", true)
                .append("span");
            elem.append("input")
                .attr("id", "reftype-" + type)
                .attr("data-type", type)
                .attr("type", "checkbox")
                .classed("form-check-input", true)
                .property("checked", true);
            elem.append("label")
                .attr("for", "reftype-" + type)
                .classed("form-check-label", true)
                .text(value["name"] + " references");
        }

        referenceFilter.selectAll("input[data-type]").on("change", event => {
            let refType = d3.select(event.target).attr("data-type");
            if (event.target.checked) {
                this.filter.refTypes.add(refType);
            } else {
                this.filter.refTypes.delete(refType)
            }
        });

        element.append(() => referenceBox.node());

        const categoryBox = d3.create("div")
            .classed("mx-3 my-3", true);
        categoryBox.append("h4")
            .text("Categories");

        const categoriesAll = categoryBox.append("button")
            .classed("btn btn-outline-primary", true)
            .text("Select all");

        const categoriesNone = categoryBox.append("button")
            .classed("btn btn-outline-primary", true)
            .text("Deselect all");

        const categoryFilter = categoryBox.append("div").classed("row", true);
        let categoryColumn;
        for (const [i, [category, value]] of Object.entries(this.categories).entries()) {
            if (i % 5 === 0) {
                categoryColumn = categoryFilter.append("div").classed("col", true);
            }
            let elem = categoryColumn.append("div")
                .classed("form-check", true)
                .append("span");
            elem.append("input")
                .attr("id", "category-" + value["id"])
                .attr("data-id", value["id"])
                .attr("type", "checkbox")
                .classed("form-check-input", true)
                .property("checked", true);
            elem.append("label")
                .attr("for", "category-" + value["id"])
                .classed("form-check-label", true)
                .text(category)
                .insert("i", ":first-child")
                .classed("fas fa-fw " + value["icon"], true);
        }

        categoryFilter.selectAll("input").on("change", event => {
            let categoryId = d3.select(event.target).attr("data-id");
            if (event.target.checked) {
                this.filter.categories.add(categoryId);
            } else {
                this.filter.categories.delete(categoryId)
            }
        });

        categoriesAll.on("click", event => {
            categoryFilter.selectAll("input")
                .property("checked", true);
            this.filter.categories = new Set(this.categoryIds);
        });

        categoriesNone.on("click", event => {
            categoryFilter.selectAll("input")
                .property("checked", false);
            this.filter.categories = new Set();
        });

        element.append(() => categoryBox.node());

        const refreshButton = d3.create("button")
            .classed("btn btn-primary mx-3 my-3", true)
            .text("Refresh");

        refreshButton.on("click", event => {
            this.update();
        })

        element.append(() => refreshButton.node());
    }

    update() {
        const colorFunc = _.partial(color, this.data.highlighted, this.statuses);

        let nodes = this.originalData.nodes;
        if (this.filter.status !== "any") {
            nodes = nodes.filter(val => val.status === this.filter.status);
        }
        nodes = nodes.filter(val => (this.filter.categories.has(val.type)));
        if (this.filter.onlyRefd) {
            nodes = nodes.filter(val => val.referenced);
        }

        let links = this.originalData.links;
        links = links.filter(val => nodes.includes(val.source) && nodes.includes(val.target));
        links = links.filter(val => _.some(_.map(val.type, type => this.filter.refTypes.has(type))));
        if (this.filter.onlyRefd) {
            let refd = new Set();
            _.each(links, val => {refd.add(val.source); refd.add(val.target)});
            nodes = nodes.filter(val => refd.has(val));
        }

        this.data = {
            nodes: nodes,
            links: links
        }

        // Update nodes
        console.log("Update nodes");
        this.nodeGroup = this.nodeGroup
            .data(this.data.nodes, function (d) {
                return d ? d.id : this.id
            })
            .join(
                enter => {
                    let g = enter.append("g");
                    g.append("a")
                        .attr("href", d => d.href)
                        .append("use")
                        .attr("xlink:href", d => "#" + d.type)
                        .attr("fill", colorFunc);
                    g.append("text")
                        .attr("fill", "#000")
                        .attr("visibility", "hidden")
                        .append("tspan")
                        .text(d => d.certid)
                        .attr("x", 20)
                        .attr("y", "0.2em")
                        .append("tspan")
                        .text(d => d.name)
                        .attr("x", 20)
                        .attr("y", "1.2em");
                    return g;
                },
                update => update,
                exit => exit.remove()
            ).call(drag(this.simulation));

        // Update links
        console.log("Update links");
        this.linkGroup = this.linkGroup
            .data(this.data.links, (d) => d.source.id + "-" + d.target.id)
            .join("line")
            .attr("stroke-width", 1)
            .attr("marker-end", "url(" + new URL("#default", location) + ")");

        // Update and restart the simulation.
        console.log("Update simulation");
        this.simulation.nodes(this.data.nodes);
        this.simulation.force("link").links(this.data.links);
        this.simulation.alpha(1).restart();

        // Update counters
        console.log("Update counters");
        this.numNodes.text("Nodes: " + this.data.nodes.length);
        this.numLinks.text("Edges: " + this.data.links.length);
    }
}

function createNetwork(element_id, data_url, types_url, status_url, refTypes_url, width, height) {
    return Promise.all([d3.json(data_url), d3.json(types_url), d3.json(status_url), d3.json(refTypes_url)]).then(values => {
        let data = values[0];
        let types = values[1];
        let statuses = values[2];
        let refTypes = values[3];
        if (("nodes" in data) && ("links" in data)) {
            let network = new CertificateNetwork(data, types, statuses, refTypes);
            network.render(element_id, width, height);
            return network;
        } else {
            console.log("Something went wrong.");
            return null;
        }
    });
}