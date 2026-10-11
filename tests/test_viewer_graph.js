'use strict';
const assert=require('node:assert/strict');
const graph=require('../linuxhound/graph.js');
const nodes=Array.from({length:350},(_,i)=>({id:'node-'+i,name:'Resource '+i,type:'file',properties:{}}));
const edges=Array.from({length:700},(_,i)=>({id:'edge-'+i,source:'node-'+(i%349),target:'node-'+((i+1)%349),type:'CanRead'}));
const full=graph.subgraph(nodes,edges);
assert.equal(full.nodes.length,350,'Overview must retain every node, including isolated node 349');
assert.equal(full.edges.length,700,'Overview must retain every relationship');
const positions=graph.layout(nodes,edges);
assert.equal(positions.positions.size,350);
for(const p of positions.positions.values()){assert.ok(Number.isFinite(p.x)&&Number.isFinite(p.y));}
const sequence=[{id:'write',source:'account',target:'file'},{id:'influence',source:'file',target:'service'},{id:'run-as',source:'service',target:'root'}];
const paths=[{id:'candidate',steps:sequence.map(e=>({edge_id:e.id}))}];
assert.equal(graph.knownPaths(paths,sequence,'account','root')[0].edges.length,3);
assert.equal(graph.knownPaths(paths,sequence,'root','account').length,0,'Reverse access must not be invented');
const unrelated={id:'read',source:'reader',target:'root'};
assert.equal(graph.knownPaths(paths,sequence.concat(unrelated),'reader','root').length,0,'An arbitrary read edge is not an attack path');
const readRoute=graph.relationshipRoute(sequence.concat(unrelated),'reader','root');
assert.equal(readRoute[0].edge.id,'read','Read connectivity is available in relationship mode');
assert.equal(readRoute[0].reversed,false);
assert.equal(graph.relationshipRoute(sequence,'root','account'),null,'Outgoing queries preserve direction');
const reverseRoute=graph.relationshipRoute(sequence,'root','account','both');
assert.equal(reverseRoute.length,3);
assert.ok(reverseRoute.every(step=>step.reversed),'Reverse exploration must be labeled');
assert.equal(reverseRoute[0].edge.source,'service','Original edge directions are retained');
assert.equal(graph.relationshipRoute(sequence,'isolated','root','both'),null);
assert.deepEqual(graph.relationshipRoute(sequence,'root','root'),[]);
assert.equal(graph.relationshipRoute([{id:'loop',source:'a',target:'a'},...sequence],'a','root','both'),null,'Cycles terminate');
const incoming=graph.targetSummary([
 {id:'one',source:'service',target:'root',type:'RunsAs'},
 {id:'two',source:'service',target:'root',type:'RunsAs'},
 {id:'other',source:'file',target:'root',type:'OwnedBy'},
 {id:'outgoing',source:'root',target:'file',type:'CanRead'},
],[],'root');
assert.equal(incoming.find(g=>g.type==='RunsAs').sourceIds.length,1,'Counts deduplicate contributors');
assert.equal(incoming.find(g=>g.type==='RunsAs').edgeIds.length,2,'Original parallel edges are retained');
assert.equal(incoming.length,2,'Outgoing links do not become incoming contributors');
const summaryPaths=[
 {id:'candidate',account_id:'account',pattern:'writable-job',steps:sequence.map(e=>({edge_id:e.id}))},
 {id:'admin',account_id:'account',pattern:'writable-job',authority:'legitimate_administrator',steps:sequence.map(e=>({edge_id:e.id}))},
 {id:'unreached',account_id:'reader',pattern:'capability',steps:[{edge_id:'read'}]},
];
const summarized=graph.targetSummary(sequence.concat({id:'read',source:'reader',target:'capability'}),summaryPaths,'root','candidate');
assert.deepEqual(summarized[0].pathIds,['candidate','admin'],'Complete administrator chains remain exposure after account compromise; unreached chains stay excluded');
assert.deepEqual(summarized[0].edgeIds,['write','influence','run-as']);
assert.deepEqual(graph.targetSummary(sequence,summaryPaths,'missing','candidate'),[]);
assert.equal(graph.subgraph(nodes,edges,new Set(['node-349'])).nodes.length,1);
assert.equal(graph.subgraph(nodes,edges,new Set(['node-349'])).edges.length,0);
const pathLayout=graph.layout(sequence.flatMap(e=>[e.source,e.target]).filter((id,i,a)=>a.indexOf(id)===i).map(id=>({id})),sequence,['account','file','service','root']);
assert.ok(pathLayout.positions.get('account').x<pathLayout.positions.get('file').x);
assert.ok(pathLayout.positions.get('file').x<pathLayout.positions.get('service').x);
assert.ok(pathLayout.positions.get('service').x<pathLayout.positions.get('root').x);
console.log('PASS: complete graph, isolated resources, bounded layout and evidence-backed directed path queries.');

assert.equal(graph.pathTone({authority:'legitimate_administrator',steps:[{}]}),'risk','Authorized power remains risk after compromise');
assert.equal(graph.pathTone({authority:'possible_unintended',steps:[{}]}),'risk');
assert.equal(graph.pathTone({verified:true}),'risk','Verified vulnerability must never be green');
assert.equal(graph.pathTone({conclusion:'conditional_attack_path',authority:'unknown'}),'risk','Conditional modeled impact remains risk');
assert.equal(graph.pathTone({classification:'coverage_gap'}),'unknown','Missing coverage must not claim safety or exploit proof');
assert.equal(graph.pathTone({authority:'unknown'}),'unknown');

const boundaryNodes=[{id:'user',type:'account',properties:{uid:1000}},{id:'file',type:'file',properties:{}},{id:'svc',type:'service',properties:{}},{id:'root',type:'account',properties:{uid:0}},{id:'docker',type:'group',name:'docker',properties:{}}];
const runAs={source:'svc',target:'root',type:'RunsAs'};
assert.equal(graph.trustBoundary({source:'user',target:'file',type:'CanWrite'},boundaryNodes,[runAs],true).kind,'supporting');
assert.equal(graph.trustBoundary({source:'file',target:'svc',type:'MayInfluence'},boundaryNodes,[runAs],true).kind,'crossing');
assert.equal(graph.trustBoundary(runAs,boundaryNodes,[runAs],true).kind,'crossing');
assert.equal(graph.trustBoundary(runAs,boundaryNodes,[runAs],false).kind,'context','RunsAs alone is not a modeled exploit');
assert.equal(graph.trustBoundary({source:'user',target:'root',type:'OwnedBy'},boundaryNodes,[runAs],true).kind,'supporting','Ownership alone is not a privilege transition');
assert.equal(graph.trustBoundary({source:'user',target:'docker',type:'MemberOf'},boundaryNodes,[runAs],true).kind,'crossing');
assert.equal(graph.trustBoundary({source:'missing',target:'root',type:'RunsAs'},boundaryNodes,[runAs],true).kind,'unknown');

const featureData={feature_names:['writable'],x:[[1],[0],[0]],x_known:[[1],[1],[0]],edge_feature_names:['sudo'],edge_x:[[1],[0]],edge_x_known:[[1],[1]]};
assert.deepEqual(graph.featureMatches(featureData,'Node','writable'),[0]);
assert.deepEqual(graph.featureMatches(featureData,'Node','writable','zero'),[1],'Unknown must not appear as known zero');
assert.deepEqual(graph.featureMatches(featureData,'Node','writable','unknown'),[2]);
assert.deepEqual(graph.featureMatches(featureData,'Node','writable','known'),[0,1]);
assert.deepEqual(graph.featureMatches(featureData,'Edge','sudo'),[0]);
assert.deepEqual(graph.featureMatches(featureData,'Node','missing'),[]);

// Reusing a trust index preserves endpoint checks and risk styling for large graphs.
{
  const modelNodes=[{id:'root',type:'account',properties:{uid:0}}, {id:'user',type:'account',properties:{uid:1000}}, {id:'job',type:'service',properties:{}}, {id:'file',type:'file',properties:{}}];
  const modelEdges=[{source:'job',target:'root',type:'RunsAs'}, {source:'file',target:'job',type:'MayInfluence'}, {source:'user',target:'file',type:'CanWrite'}, {source:'missing',target:'root',type:'SudoAllows'}];
  const index=graph.trustContext(modelNodes,modelEdges);
  for(const edge of modelEdges)for(const risk of [false,true])assert.deepStrictEqual(graph.trustBoundary(edge,modelNodes,modelEdges,risk,index),graph.trustBoundary(edge,modelNodes,modelEdges,risk));
  assert(index.rootConsumers.has('job'));
}

assert.equal(graph.initialView(nodes,edges),'all');
assert.equal(graph.initialView(nodes,Array.from({length:2001},()=>edges[0])),'summary');
assert.equal(graph.initialView(Array.from({length:351},()=>nodes[0]),[]),'summary');
// Presentation choice does not remove any original resources or relationships.
assert.equal(graph.subgraph(nodes,edges).edges.length,edges.length);

assert.equal(graph.motionAllowed(true,40,203),true);
assert.equal(graph.motionAllowed(false,4,3),false);
assert.equal(graph.motionAllowed(true,782,19735),false);
assert.equal(graph.motionAllowed(true,30,501),false);
