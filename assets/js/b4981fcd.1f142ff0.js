"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[2961],{3905:(e,t,n)=>{n.d(t,{Zo:()=>u,kt:()=>m});var a=n(7294);function o(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function r(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function l(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?r(Object(n),!0).forEach((function(t){o(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):r(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,a,o=function(e,t){if(null==e)return{};var n,a,o={},r=Object.keys(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||(o[n]=e[n]);return o}(e,t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var c=a.createContext({}),i=function(e){var t=a.useContext(c),n=t;return e&&(n="function"==typeof e?e(t):l(l({},t),e)),n},u=function(e){var t=i(e.components);return a.createElement(c.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},d=a.forwardRef((function(e,t){var n=e.components,o=e.mdxType,r=e.originalType,c=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),d=i(n),m=o,h=d["".concat(c,".").concat(m)]||d[m]||p[m]||r;return n?a.createElement(h,l(l({ref:t},u),{},{components:n})):a.createElement(h,l({ref:t},u))}));function m(e,t){var n=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var r=n.length,l=new Array(r);l[0]=d;var s={};for(var c in t)hasOwnProperty.call(t,c)&&(s[c]=t[c]);s.originalType=e,s.mdxType="string"==typeof e?e:o,l[1]=s;for(var i=2;i<r;i++)l[i]=n[i];return a.createElement.apply(null,l)}return a.createElement.apply(null,n)}d.displayName="MDXCreateElement"},5162:(e,t,n)=>{n.d(t,{Z:()=>l});var a=n(7294),o=n(6010);const r="tabItem_Ymn6";function l(e){let{children:t,hidden:n,className:l}=e;return a.createElement("div",{role:"tabpanel",className:(0,o.Z)(r,l),hidden:n},t)}},5488:(e,t,n)=>{n.d(t,{Z:()=>m});var a=n(7462),o=n(7294),r=n(6010),l=n(2389),s=n(7392),c=n(7094),i=n(2466);const u="tabList__CuJ",p="tabItem_LNqP";function d(e){var t;const{lazy:n,block:l,defaultValue:d,values:m,groupId:h,className:y}=e,g=o.Children.map(e.children,(e=>{if((0,o.isValidElement)(e)&&"value"in e.props)return e;throw new Error(`Docusaurus error: Bad <Tabs> child <${"string"==typeof e.type?e.type:e.type.name}>: all children of the <Tabs> component should be <TabItem>, and every <TabItem> should have a unique "value" prop.`)})),k=m??g.map((e=>{let{props:{value:t,label:n,attributes:a}}=e;return{value:t,label:n,attributes:a}})),f=(0,s.l)(k,((e,t)=>e.value===t.value));if(f.length>0)throw new Error(`Docusaurus error: Duplicate values "${f.map((e=>e.value)).join(", ")}" found in <Tabs>. Every value needs to be unique.`);const b=null===d?d:d??(null==(t=g.find((e=>e.props.default)))?void 0:t.props.value)??g[0].props.value;if(null!==b&&!k.some((e=>e.value===b)))throw new Error(`Docusaurus error: The <Tabs> has a defaultValue "${b}" but none of its children has the corresponding value. Available values are: ${k.map((e=>e.value)).join(", ")}. If you intend to show no default tab, use defaultValue={null} instead.`);const{tabGroupChoices:v,setTabGroupChoices:w}=(0,c.U)(),[N,S]=(0,o.useState)(b),O=[],{blockElementScrollPositionUntilNextRender:T}=(0,i.o5)();if(null!=h){const e=v[h];null!=e&&e!==N&&k.some((t=>t.value===e))&&S(e)}const E=e=>{const t=e.currentTarget,n=O.indexOf(t),a=k[n].value;a!==N&&(T(t),S(a),null!=h&&w(h,String(a)))},P=e=>{var t;let n=null;switch(e.key){case"Enter":E(e);break;case"ArrowRight":{const t=O.indexOf(e.currentTarget)+1;n=O[t]??O[0];break}case"ArrowLeft":{const t=O.indexOf(e.currentTarget)-1;n=O[t]??O[O.length-1];break}}null==(t=n)||t.focus()};return o.createElement("div",{className:(0,r.Z)("tabs-container",u)},o.createElement("ul",{role:"tablist","aria-orientation":"horizontal",className:(0,r.Z)("tabs",{"tabs--block":l},y)},k.map((e=>{let{value:t,label:n,attributes:l}=e;return o.createElement("li",(0,a.Z)({role:"tab",tabIndex:N===t?0:-1,"aria-selected":N===t,key:t,ref:e=>O.push(e),onKeyDown:P,onClick:E},l,{className:(0,r.Z)("tabs__item",p,null==l?void 0:l.className,{"tabs__item--active":N===t})}),n??t)}))),n?(0,o.cloneElement)(g.filter((e=>e.props.value===N))[0],{className:"margin-top--md"}):o.createElement("div",{className:"margin-top--md"},g.map(((e,t)=>(0,o.cloneElement)(e,{key:t,hidden:e.props.value!==N})))))}function m(e){const t=(0,l.Z)();return o.createElement(d,(0,a.Z)({key:String(t)},e))}},7:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>u,contentTitle:()=>c,default:()=>m,frontMatter:()=>s,metadata:()=>i,toc:()=>p});var a=n(7462),o=(n(7294),n(3905)),r=n(5488),l=n(5162);const s={sidebar_label:"Quickstart \ud83d\ude80"},c="Quickstart (Nango Sync)",i={unversionedId:"nango-sync/quickstart",id:"nango-sync/quickstart",title:"Quickstart (Nango Sync)",description:"Goal",source:"@site/docs/nango-sync/quickstart.md",sourceDirName:"nango-sync",slug:"/nango-sync/quickstart",permalink:"/nango-sync/quickstart",draft:!1,editUrl:"https://github.com/nangohq/nango/tree/main/docs/docs/nango-sync/quickstart.md",tags:[],version:"current",frontMatter:{sidebar_label:"Quickstart \ud83d\ude80"},sidebar:"docsSidebar",previous:{title:"Introduction",permalink:"/sync"},next:{title:"Core concepts",permalink:"/nango-sync/use-nango/core-concepts"}},u={},p=[{value:"Step 1: Download &amp; run Nango Sync",id:"step-1-download--run-nango-sync",level:2},{value:"Step 2: Create a new Sync",id:"step-2-create-a-new-sync",level:2},{value:"Step 3: Inspect the synced <del>data</del> Pok\xe9mons",id:"step-3-inspect-the-synced-data-pok\xe9mons",level:2},{value:"That&#39;s it!",id:"thats-it",level:2}],d={toc:p};function m(e){let{components:t,...n}=e;return(0,o.kt)("wrapper",(0,a.Z)({},d,n,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h1",{id:"quickstart-nango-sync"},"Quickstart (Nango Sync)"),(0,o.kt)("p",null,(0,o.kt)("strong",{parentName:"p"},"Goal"),(0,o.kt)("br",{parentName:"p"}),"\n","Show you Nango Sync in action by syncing a list of all Pok\xe9mons to your local DB ",(0,o.kt)("strong",{parentName:"p"},"in 3 minutes"),"."),(0,o.kt)("p",null,(0,o.kt)("strong",{parentName:"p"},"Prerequisite"),(0,o.kt)("br",{parentName:"p"}),"\n","Before we dive in, make sure you have a recent version of ",(0,o.kt)("a",{parentName:"p",href:"https://www.docker.com/products/docker-desktop/"},"Docker")," installed."),(0,o.kt)("p",null,"Ready? Let's go!"),(0,o.kt)("h2",{id:"step-1-download--run-nango-sync"},"Step 1: Download & run Nango Sync"),(0,o.kt)("p",null,"In a directory of your choice run:"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre",className:"language-bash"},"git clone https://github.com/NangoHQ/nango-sync.git\n")),(0,o.kt)("p",null,"And then start Nango Sync:"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre",className:"language-bash"},"cd nango-sync && docker compose up  # cd nango-sync && docker-compose up if you are on an older version of docker\n")),(0,o.kt)("h2",{id:"step-2-create-a-new-sync"},"Step 2: Create a new Sync"),(0,o.kt)("p",null,"Next we need to tell Nango Sync about our Sync job: Here we want it to fetch the latest details about all Pok\xe9mons from the ",(0,o.kt)("a",{parentName:"p",href:"https://pokeapi.co/"},"Pok\xe9 API")," and sync it to our local database."),(0,o.kt)("p",null,"To do this run the following CURL command in the terminal (we use Nango Sync's REST API here to create a new Sync):"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre",className:"language-bash"},'  curl --request POST \\\n    --url http://localhost:3003/v1/syncs \\\n    --header "Content-type: application/json" \\\n    --data \'{"url": "https://pokeapi.co/api/v2/pokemon", "response_path": "results", "paging_url_path":"next", "mapped_table":"pokemons", "frequency":"1 minute"}\'\n')),(0,o.kt)("p",null,"That's it! You have just created your 1st Sync :)"),(0,o.kt)("p",null,"While CURL is great for testing things locally, in your code you will probably prefer using one of our native SDKs to create syncs on the fly (e.g. when a user activates a new native integration)."),(0,o.kt)("p",null,"Here is what the above CURL command looks like with our SDKs:"),(0,o.kt)(r.Z,{groupId:"programming-language",mdxType:"Tabs"},(0,o.kt)(l.Z,{value:"node",label:"Node SDK",mdxType:"TabItem"},(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre",className:"language-js"},"import { Nango } from '@nangohq/node-client';\n\nlet config = {\n    response_path: 'results', // For finding records in the API response.\n    paging_url_path: 'next', // For finding pagination data in responses.\n    mapped_table: 'pokemons', // We want the data to be synced to a table called \"pokemons\"\n    frequency: '1 minute' // How often the data is refreshed from the external API.\n};\n\nlet res = await new Nango().sync('https://pokeapi.co/api/v2/pokemon', config);\n\nconsole.log(res.data);\n")))),(0,o.kt)("h2",{id:"step-3-inspect-the-synced-data-pok\xe9mons"},"Step 3: Inspect the synced ",(0,o.kt)("del",{parentName:"h2"},"data")," Pok\xe9mons"),(0,o.kt)("p",null,"The Sync you just created will keep your Pok\xe9mon list up-to-date forever.",(0,o.kt)("br",{parentName:"p"}),"\n","View ",(0,o.kt)("a",{parentName:"p",href:"http://localhost:8080/?pgsql=nango-db&username=nango&db=nango&ns=nango&select=pokemons"},"the list of all Pok\xe9mons")," in your local db (password is ",(0,o.kt)("inlineCode",{parentName:"p"},"nango"),")."),(0,o.kt)("h2",{id:"thats-it"},"That's it!"),(0,o.kt)("p",null,"Congratulations, you now have a local copy of all Pok\xe9mons in your database \ud83c\udf89",(0,o.kt)("br",{parentName:"p"}),"\n","It's yours to keep."),(0,o.kt)("p",null,"Whilst this is just a small toy example we hope it has shown you how Nango Sync can create powerful syncs with a single line of code."),(0,o.kt)("p",null,"When you are ready here are some suggestions to get the most out of Nango Sync:"),(0,o.kt)("ul",null,(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/nango-sync/use-nango/core-concepts"},"Explore the core concepts")," - our recommended way to get started and learn more about Nango"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"https://nango.dev/slack"},"Join the Slack Community")," and give us feedback on the quickstart & Nango"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/nango-sync/real-world-examples"},"Explore more examples")),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/nango-sync/architecture"},"Explore the Architecture")),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/nango-sync/contributing"},"Contribute \u2764\ufe0f"))))}m.isMDXComponent=!0}}]);