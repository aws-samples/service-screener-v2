import json
from utils.CustomPage.CustomPageBuilder import CustomPageBuilder
from utils.Config import Config

class ModernizePageBuilder(CustomPageBuilder):
    nodes = {}
    links = {}
    
    def customPageInit(self):
        self.addJSLib('https://d3js.org/d3.v5.min.js')
        self.addJSLib('https://unpkg.com/d3-sankey@0.7.1/build/d3-sankey.js')
    
    def d3FormatNodes(self):
        nodes = []
        c=0
        
        for p, data in self.data.ds.items():
            nodes = []
            for node in data['nodes']:
                nodes.append({'name': node})
        
            self.nodes[c] = nodes
            self.links[c] = data['links']
            c=c+1
    
    def buildContentSummary_customPage(self):
        output = []
        output.append("")
        output.append("<svg id='compute' xmlns='http://www.w3.org/2000/svg' ></svg>")
        output.append("<svg id='database' xmlns='http://www.w3.org/2000/svg' ></svg>")
        output.append 
        return output
    
    def buildContentDetail_customPage(self):
        self.d3FormatNodes()
        
        self.addJS("""
    const width = 1650;
    const height = 500;
    
    var vnodes = {node0}
    var vlinks = {link0}
    buildD3Sankey('#compute', vnodes, vlinks)
    
    vnodes = {node1}
    vlinks = {link1}
    buildD3Sankey('#database', vnodes, vlinks)
    """.format(
        node0 = json.dumps(self.nodes[0]),
        link0 = json.dumps(self.links[0]),
        node1 = json.dumps(self.nodes[1]),
        link1 = json.dumps(self.links[1])
    ))
    
        self.addJS("""    
    function buildD3Sankey(eleId, vnodes, vlinks){
        let edgeColor = 'path';
    
        const _sankey = d3.sankey()
            .nodeAlign(d3.sankeyLeft)
            .nodeWidth(15)
            .nodePadding(10)
            .extent([[1, 1], [width - 1, height - 200]]);
        
        const sankey = ({nodes, links}) => _sankey({
            nodes: nodes.map(d => Object.assign({}, d)),
            links: links.map(d => Object.assign({}, d))
        });
    
    
        const f = d3.format(",.0f");
        const format = d => `# ${f(d)} `;
    
        const _color = d3.scaleOrdinal(d3.schemeCategory10);
        const color = name => _color(name.replace(/ .*/, ""));
    
        const svg = d3.select(eleId)
            .attr("viewBox", `0 0 ${width} ${height}`)
            .style("width", "100%")
            .style("height", "100%");
    
          data = {
              "nodes":vnodes,
              "links":vlinks
          }
          const {nodes, links} = sankey(data);
    
          svg.append("g")
              .attr("stroke", "#000")
              .selectAll("rect")
              .data(nodes)
              .join("rect")
              .attr("x", d => d.x0)
              .attr("y", d => d.y0)
              .attr("height", d => d.y1 - d.y0)
              .attr("width", d => d.x1 - d.x0)
              .attr("fill", d => color(d.name))
              .append("title")
              .text(d => `${d.name}
                ${format(d.value)}`);
    
          const link = svg.append("g")
              .attr("fill", "none")
              .attr("stroke-opacity", 0.5)
              .selectAll("g")
              .data(links)
              .join("g")
              .style("mix-blend-mode", "multiply");
    
          function update() {
              if (edgeColor === "path") {
                  const gradient = link.append("linearGradient")
                      .attr("id", (d,i) => {
                      const id = `link-${i}`;
                      d.uid = `url(#${id})`;
                      return id;
                      })
                      .attr("gradientUnits", "userSpaceOnUse")
                      .attr("x1", d => d.source.x1)
                      .attr("x2", d => d.target.x0);
    
                  gradient.append("stop")
                      .attr("offset", "0%")
                      .attr("stop-color", d => color(d.source.name));
    
                  gradient.append("stop")
                      .attr("offset", "100%")
                      .attr("stop-color", d => color(d.target.name));
              }
    
              link.append("path")
                  .attr("d", d3.sankeyLinkHorizontal())
                  .attr("stroke", d => edgeColor === "path" ? d.uid
                      : edgeColor === "input" ? color(d.source.name)
                      : color(d.target.name))
                  .attr("stroke-width", d => Math.max(1, d.width));
          }
                  
          update();
    
          link.append("title")
              .text(d => `${d.source.name} → ${d.target.name}
                  ${format(d.value)}`);
    
          svg.append("g")
              .style("font", "10px sans-serif")
              .selectAll("text")
              .data(nodes)
              .join("text")
              .attr("x", d => d.x0 < width / 2 ? d.x1 + 6 : d.x0 - 6)
              .attr("y", d => (d.y1 + d.y0) / 2)
              .attr("dy", "0.35em")
              .attr("text-anchor", d => d.x0 < width / 2 ? "start" : "end")
              .text(d => d.name);
    
              
    }
    """)