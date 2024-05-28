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
                n = node
                if node == 'TagsKeyWords':
                    n = '**' + node
                
                nodes.append({'name': n})
        
            self.nodes[c] = nodes
            self.links[c] = data['links']
            c=c+1
    
    def buildContentSummary_customPage(self):
        output = []
        
        html = "[Beta] (For Sankey diagram to generate, internet connectivty is required. The page loads D3 Javascript directly from d3 CDN) Modernizing your applications helps you reduce costs, gain efficiencies, and make the most of your existing investments. It involves a multi-dimensional approach to adopt and use new technology, to deliver portfolio, application, and infrastructure value faster, and to position your organization to scale at an optimal price. After you optimize your applications, you must operate in that new, modernized model without disruption to simplify your business operations, architecture, and overall engineering practices.<br><br>Migrating applications to AWS by using the rehosting (lift and shift) approach doesn’t automatically give you the benefits of the elasticity, resiliency, ease of deployment and management, and flexibility that AWS offers. Nor does it automatically modernize your culture and processes to enable high-performing software development. Modernization means taking your application environment in the form that it’s in today (most likely, legacy and monolithic) and transforming it into something that is more agile, elastic, and highly available. In doing so, you can transform your business into a modern enterprise.<br><br>To optimize your cloud adoption and migration, you must first assess and evaluate your enterprise for readiness. After you assess the readiness of your organization, you can:<br><ol><li>Select one or two applications.</li><li>Modernize those applications so that you can maintain, extend, deploy, and manage them in a way that meets the current and future needs of your business.</li><li>Establish a foundation for modernization at scale through the hands-on experience you gained in the previous two steps. In this phase, you can create a complete modernization solution by determining the supporting infrastructure, application middleware, middleware services (such as databases, queuing software, integration software, and other technologies), and other components.</li></ol><br>The iterative approach to application modernization discussed in this article can be divided into three high-level phases: assess, modernize, and manage.<br><br>The modernisation sankey belows provide recommendation of your environment the next possible service or feature to leverage to achieve optimized architecture on AWS. Read more <a target=_blank rel='noopener noreferrer' href='https://docs.aws.amazon.com/prescriptive-guidance/latest/strategy-modernizing-applications/welcome.html'>here</a>"
        card = self.generateCard(pid=self.getHtmlId('Description'), html=html, cardClass='warning', title='Read Me', titleBadge='', collapse=True, noPadding=False)
        items = [[card, '']]
        
        output.append(self.generateRowWithCol(size=12, items=items, rowHtmlAttr="data-context='description'"))
        
        
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