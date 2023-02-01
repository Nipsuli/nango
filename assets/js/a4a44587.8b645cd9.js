"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[6394],{3905:(e,n,t)=>{t.d(n,{Zo:()=>s,kt:()=>m});var o=t(7294);function a(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function r(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);n&&(o=o.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,o)}return t}function l(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?r(Object(t),!0).forEach((function(n){a(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):r(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function i(e,n){if(null==e)return{};var t,o,a=function(e,n){if(null==e)return{};var t,o,a={},r=Object.keys(e);for(o=0;o<r.length;o++)t=r[o],n.indexOf(t)>=0||(a[t]=e[t]);return a}(e,n);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(o=0;o<r.length;o++)t=r[o],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(a[t]=e[t])}return a}var p=o.createContext({}),c=function(e){var n=o.useContext(p),t=n;return e&&(t="function"==typeof e?e(n):l(l({},n),e)),t},s=function(e){var n=c(e.components);return o.createElement(p.Provider,{value:n},e.children)},u={inlineCode:"code",wrapper:function(e){var n=e.children;return o.createElement(o.Fragment,{},n)}},d=o.forwardRef((function(e,n){var t=e.components,a=e.mdxType,r=e.originalType,p=e.parentName,s=i(e,["components","mdxType","originalType","parentName"]),d=c(t),m=a,g=d["".concat(p,".").concat(m)]||d[m]||u[m]||r;return t?o.createElement(g,l(l({ref:n},s),{},{components:t})):o.createElement(g,l({ref:n},s))}));function m(e,n){var t=arguments,a=n&&n.mdxType;if("string"==typeof e||a){var r=t.length,l=new Array(r);l[0]=d;var i={};for(var p in n)hasOwnProperty.call(n,p)&&(i[p]=n[p]);i.originalType=e,i.mdxType="string"==typeof e?e:a,l[1]=i;for(var c=2;c<r;c++)l[c]=t[c];return o.createElement.apply(null,l)}return o.createElement.apply(null,t)}d.displayName="MDXCreateElement"},4743:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>p,contentTitle:()=>l,default:()=>u,frontMatter:()=>r,metadata:()=>i,toc:()=>c});var o=t(7462),a=(t(7294),t(3905));const r={},l="Deploy Nango to GCP (Compute Engine)",i={unversionedId:"nango-deploy/gcp",id:"nango-deploy/gcp",title:"Deploy Nango to GCP (Compute Engine)",description:"Deploy Nango on GCP in less than 5 minutes.",source:"@site/docs/nango-deploy/gcp.md",sourceDirName:"nango-deploy",slug:"/nango-deploy/gcp",permalink:"/nango-deploy/gcp",draft:!1,editUrl:"https://github.com/nangohq/nango/tree/main/docs/docs/nango-deploy/gcp.md",tags:[],version:"current",frontMatter:{},sidebar:"nango",previous:{title:"Deploy Nango to AWS (EC2)",permalink:"/nango-deploy/aws"},next:{title:"Deploy Nango to Digital Ocean (Droplet)",permalink:"/nango-deploy/digital-ocean"}},p={},c=[{value:"Create a VM",id:"create-vm",level:2},{value:"Install Docker",id:"install-docker",level:2},{value:"Run Nango",id:"run-nango",level:2},{value:"Update Nango",id:"update-nango",level:2},{value:"Limitations &amp; production use",id:"limitations--production-use",level:2}],s={toc:c};function u(e){let{components:n,...t}=e;return(0,a.kt)("wrapper",(0,o.Z)({},s,t,{components:n,mdxType:"MDXLayout"}),(0,a.kt)("h1",{id:"deploy-nango-to-gcp-compute-engine"},"Deploy Nango to GCP (Compute Engine)"),(0,a.kt)("p",null,"Deploy Nango on GCP in less than 5 minutes."),(0,a.kt)("h2",{id:"create-vm"},"Create a VM"),(0,a.kt)("p",null,"Go to the ",(0,a.kt)("a",{parentName:"p",href:"https://console.cloud.google.com/compute/instances"},"Compute Engine service")," and click ",(0,a.kt)("em",{parentName:"p"},"CREATE INSTANCE"),". Create an instance with default settings except: "),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("inlineCode",{parentName:"li"},"e2-medium")," for testing, ",(0,a.kt)("inlineCode",{parentName:"li"},"e2-standard-2")," for production"),(0,a.kt)("li",{parentName:"ul"},"Enable ",(0,a.kt)("em",{parentName:"li"},"Allow HTTP traffic")," and ",(0,a.kt)("em",{parentName:"li"},"Allow HTTPS traffic"))),(0,a.kt)("h2",{id:"install-docker"},"Install Docker"),(0,a.kt)("p",null,"Go to your Compute Engine instance page and click ",(0,a.kt)("em",{parentName:"p"},"SSH"),"."),(0,a.kt)("p",null,"Install Docker & Docker Compose with the following commands:"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},'sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl gnupg2 software-properties-common wget\ncurl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add --\nsudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian buster stable"\nsudo apt-get update\nsudo apt-get install -y docker-ce docker-ce-cli containerd.io\nsudo usermod -a -G docker $USER\ncurl -s https://api.github.com/repos/docker/compose/releases/latest | grep browser_download_url  | grep docker-compose-linux-x86_64 | cut -d \'"\' -f 4 | wget -qi -\nchmod +x docker-compose-linux-x86_64 && sudo mv docker-compose-linux-x86_64 /usr/local/bin/docker-compose\ndocker-compose --version\n')),(0,a.kt)("admonition",{type:"info"},(0,a.kt)("p",{parentName:"admonition"},"Refresh the VM console page to activate the new configuration.")),(0,a.kt)("h2",{id:"run-nango"},"Run Nango"),(0,a.kt)("p",null,"Still in your VM\u2019s console, install Nango by running: "),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"mkdir nango && cd nango\nwget https://raw.githubusercontent.com/NangoHQ/nango/main/docker/aws/docker-compose.yaml && wget https://raw.githubusercontent.com/NangoHQ/nango/main/.env\ndocker-compose up -d # Nango is now running!\n")),(0,a.kt)("h2",{id:"update-nango"},"Update Nango"),(0,a.kt)("p",null,"In your VM\u2019s console, run:"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"docker-compose stop\ndocker-compose rm -f\ndocker-compose pull\ndocker-compose up -d\n")),(0,a.kt)("h2",{id:"limitations--production-use"},"Limitations & production use"),(0,a.kt)("p",null,"The open-source setup has been optimized for quick deployment and local usage. Before you deploy open source Nango to production we recommend you read about the ",(0,a.kt)("a",{parentName:"p",href:"/nango-deploy/oss-limitations"},"production limitations")," and mitigate them."))}u.isMDXComponent=!0}}]);