'use strict';
const LinuxHoundGraph = (() => {
  function pathTone(path) {
    if(path.conclusion==='coverage_gap'||path.classification==='coverage_gap')return 'unknown';
    return path.verified||['verified_vulnerability','conditional_attack_path','conditional_administrator_authority'].includes(path.conclusion)||
      (path.steps?.length&&['legitimate_administrator','possible_unintended'].includes(path.authority))?'risk':'unknown';
  }
  function motionAllowed(enabled, nodeCount, edgeCount) {
    return Boolean(enabled)&&nodeCount<=250&&edgeCount<=500;
  }
  function initialView(nodes, edges) {
    return nodes.length>350||edges.length>2000?'summary':'all';
  }
  function trustContext(nodes, edges) {
    const byId=new Map(nodes.map(n=>[n.id,n]));
    const rootConsumers=new Set(edges.filter(e=>e.type==='RunsAs'&&byId.get(e.target)?.type==='account'&&byId.get(e.target)?.properties?.uid===0).map(e=>e.source));
    return {byId,rootConsumers};
  }
  function trustBoundary(edge, nodes, edges, modeledRisk=false, context=null) {
    const index=context||trustContext(nodes,edges),byId=index.byId,source=byId.get(edge.source),target=byId.get(edge.target);
    if(!source||!target)return {kind:'unknown',reason:'Endpoint metadata is missing.'};
    if(!modeledRisk)return {kind:'context',reason:'Collected relationship; no modeled privilege crossing established.'};
    const root=n=>n?.type==='account'&&n.properties?.uid===0;
    const rootConsumer=n=>index.rootConsumers.has(n.id);
    if(edge.type==='SudoAllows'&&root(target)&&!root(source))return {kind:'crossing',reason:'Sudo policy permits execution as root; command and authentication prerequisites still apply.'};
    if(edge.type==='MayInfluence'&&rootConsumer(target))return {kind:'crossing',reason:'Potential influence over a root-run consumer; code execution and job activation are prerequisites.'};
    if(edge.type==='RunsAs'&&root(target))return {kind:'crossing',reason:'The modeled chain reaches execution in the root identity.'};
    if(edge.type==='MemberOf'&&target.type==='group'&&target.name==='docker')return {kind:'crossing',reason:'Membership enters Docker administration; live socket access and daemon authority remain prerequisites.'};
    if(edge.type==='HasCapability'&&target.type==='capability'&&['cap_setuid','cap_setgid','cap_sys_admin','cap_dac_override','cap_dac_read_search'].includes(target.name))return {kind:'crossing',reason:'Executable carries elevated kernel authority; executable behavior remains a prerequisite.'};
    return {kind:'supporting',reason:'Supporting step in a modeled risk chain; an authority transition is not established on this edge.'};
  }
  function featureMatches(data,kind,feature,mode='nonzero') {
    const names=kind==='Node'?data.feature_names:data.edge_feature_names;
    const rows=kind==='Node'?data.x:data.edge_x,masks=kind==='Node'?data.x_known:data.edge_x_known;
    const index=(names||[]).indexOf(feature);if(index<0)return [];
    const result=[];
    (rows||[]).forEach((row,i)=>{const known=masks?.[i]?.[index]===1,value=row[index];
      if(mode==='unknown'?!known:known&&Number.isFinite(value)&&(mode==='known'||(mode==='zero'?value===0:value!==0)))result.push(i);
    });
    return result;
  }
  function subgraph(nodes, edges, nodeIds=null, edgeIds=null) {
    const selected=nodes.filter(n=>!nodeIds||nodeIds.has(n.id));
    const ids=new Set(selected.map(n=>n.id));
    return {nodes:selected,edges:edges.filter(e=>ids.has(e.source)&&ids.has(e.target)&&(!edgeIds||edgeIds.has(e.id)))};
  }
  function route(edges, source, target) {
    if(source===target)return [];
    const adj=new Map();
    edges.forEach(e=>{if(!adj.has(e.source))adj.set(e.source,[]);adj.get(e.source).push(e);});
    const queue=[source],previous=new Map([[source,null]]);
    for(let i=0;i<queue.length;i++){
      for(const edge of adj.get(queue[i])||[]){
        if(previous.has(edge.target))continue;
        previous.set(edge.target,edge);queue.push(edge.target);
        if(edge.target===target){const result=[];let id=target;while(id!==source){const step=previous.get(id);result.unshift(step);id=step.source;}return result;}
      }
    }
    return null;
  }
  function knownPaths(paths, edges, source, target) {
    const byId=new Map(edges.map(e=>[e.id,e]));
    const result=[];
    for(const path of paths){
      const steps=(path.steps||[]).map(s=>byId.get(s.edge_id)).filter(Boolean);
      const sequence=route(steps,source,target);
      if(sequence&&sequence.length)result.push({path,edges:sequence});
    }
    return result.sort((a,b)=>a.edges.length-b.edges.length||a.path.id.localeCompare(b.path.id));
  }
  function relationshipRoute(edges, source, target, direction='outgoing') {
    if(source===target)return [];
    const adj=new Map();
    function append(from,to,edge,reversed){if(!adj.has(from))adj.set(from,[]);adj.get(from).push({from,to,edge,reversed});}
    for(const edge of edges){append(edge.source,edge.target,edge,false);if(direction==='both')append(edge.target,edge.source,edge,true);}
    const queue=[source],previous=new Map([[source,null]]);
    for(let i=0;i<queue.length;i++)for(const step of adj.get(queue[i])||[]){
      if(previous.has(step.to))continue;
      previous.set(step.to,step);queue.push(step.to);
      if(step.to===target){const result=[];let id=target;while(id!==source){const item=previous.get(id);result.unshift(item);id=item.from;}return result;}
    }
    return null;
  }
  function targetSummary(edges, paths, target, scope='incoming') {
    const groups=new Map(),byId=new Map(edges.map(e=>[e.id,e]));
    function group(key){if(!groups.has(key))groups.set(key,{type:key,sourceIds:new Set(),edgeIds:new Set(),pathIds:new Set()});return groups.get(key);}
    if(scope==='candidate'){
      for(const path of paths){
        const steps=(path.steps||[]).map(s=>byId.get(s.edge_id)).filter(Boolean);
        const start=path.account_id||steps[0]?.source;
        const chain=route(steps,start,target);
        if(!chain||!chain.length)continue;
        const g=group(path.pattern||'candidate');g.sourceIds.add(start);g.pathIds.add(path.id);chain.forEach(e=>g.edgeIds.add(e.id));
      }
    }else{
      for(const edge of edges){if(edge.target!==target)continue;const g=group(edge.type);g.sourceIds.add(edge.source);g.edgeIds.add(edge.id);}
    }
    return [...groups.values()].map(g=>({...g,sourceIds:[...g.sourceIds],edgeIds:[...g.edgeIds],pathIds:[...g.pathIds]}))
      .sort((a,b)=>b.sourceIds.length-a.sourceIds.length||a.type.localeCompare(b.type));
  }
  function layout(nodes, edges, orderedIds=null) {
    const positions=new Map();
    if(orderedIds){
      const order=[...new Set(orderedIds)].filter(id=>nodes.some(n=>n.id===id));
      const extras=nodes.filter(n=>!order.includes(n.id)).map(n=>n.id);
      order.forEach((id,i)=>positions.set(id,{x:130+i*250,y:190}));
      extras.forEach((id,i)=>positions.set(id,{x:130+i*220,y:400}));
      return {positions,width:Math.max(700,order.length*250),height:extras.length?560:420};
    }
    const ids=new Set(nodes.map(n=>n.id)),adj=new Map(nodes.map(n=>[n.id,[]]));
    edges.forEach(e=>{if(ids.has(e.source)&&ids.has(e.target)){adj.get(e.source).push(e.target);adj.get(e.target).push(e.source);}});
    const visited=new Set(),components=[];
    for(const node of nodes){if(visited.has(node.id))continue;const queue=[node.id];visited.add(node.id);for(let i=0;i<queue.length;i++){for(const id of adj.get(queue[i])){if(!visited.has(id)){visited.add(id);queue.push(id);}}}components.push(queue);}
    components.sort((a,b)=>b.length-a.length);
    const columns=Math.max(1,Math.ceil(Math.sqrt(components.length))),cells=[];
    let offsetY=90,maxWidth=700;
    for(let row=0;row<components.length;row+=columns){
      let offsetX=90,rowHeight=0;
      for(const component of components.slice(row,row+columns)){
        const span=Math.max(240,Math.sqrt(component.length)*175);
        const local=new Map();
        component.forEach((id,i)=>{const angle=i*2.39996323,r=component.length===1?0:Math.sqrt(i+.5)*57;local.set(id,{x:span/2+Math.cos(angle)*r,y:span/2+Math.sin(angle)*r});});
        if(component.length>1&&component.length<=250){
          const links=[...new Map(edges.filter(e=>local.has(e.source)&&local.has(e.target)).map(e=>[[e.source,e.target].sort().join('|'),e])).values()];
          for(let iteration=0;iteration<100;iteration++){
            const delta=new Map(component.map(id=>[id,{x:0,y:0}]));
            for(let i=0;i<component.length;i++)for(let j=i+1;j<component.length;j++){
              const a=local.get(component[i]),b=local.get(component[j]),dx=a.x-b.x,dy=a.y-b.y,d=Math.max(15,Math.hypot(dx,dy)),f=8000/(d*d);
              delta.get(component[i]).x+=dx/d*f;delta.get(component[i]).y+=dy/d*f;delta.get(component[j]).x-=dx/d*f;delta.get(component[j]).y-=dy/d*f;
            }
            links.forEach(e=>{const a=local.get(e.source),b=local.get(e.target),dx=b.x-a.x,dy=b.y-a.y,d=Math.max(1,Math.hypot(dx,dy)),f=(d-165)*.006;delta.get(e.source).x+=dx/d*f;delta.get(e.source).y+=dy/d*f;delta.get(e.target).x-=dx/d*f;delta.get(e.target).y-=dy/d*f;});
            component.forEach(id=>{const p=local.get(id),v=delta.get(id);p.x+=Math.max(-8,Math.min(8,v.x));p.y+=Math.max(-8,Math.min(8,v.y));});
          }
        }
        let minX=Infinity,minY=Infinity,maxX=-Infinity,maxY=-Infinity;
        local.forEach(p=>{minX=Math.min(minX,p.x);minY=Math.min(minY,p.y);maxX=Math.max(maxX,p.x);maxY=Math.max(maxY,p.y);});
        const w=Math.max(210,maxX-minX+230),h=Math.max(200,maxY-minY+190);
        local.forEach((p,id)=>positions.set(id,{x:p.x-minX+offsetX+80,y:p.y-minY+offsetY+50}));
        cells.push({x:offsetX,y:offsetY,w,h});offsetX+=w+40;rowHeight=Math.max(rowHeight,h);maxWidth=Math.max(maxWidth,offsetX+50);
      }
      offsetY+=rowHeight+55;
    }
    return {positions,width:maxWidth,height:Math.max(500,offsetY),components:components.length};
  }
  return {featureMatches,motionAllowed,initialView,trustContext,trustBoundary,pathTone,subgraph,route,knownPaths,relationshipRoute,targetSummary,layout};
})();
if(typeof module!=='undefined'&&module.exports)module.exports=LinuxHoundGraph;
