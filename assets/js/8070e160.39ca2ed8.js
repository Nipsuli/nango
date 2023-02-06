"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[2651],{3905:(e,t,r)=>{r.d(t,{Zo:()=>p,kt:()=>g});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function c(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?o(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},o=Object.keys(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var u=n.createContext({}),i=function(e){var t=n.useContext(u),r=t;return e&&(r="function"==typeof e?e(t):c(c({},t),e)),r},p=function(e){var t=i(e.components);return n.createElement(u.Provider,{value:t},e.children)},l={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},d=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,o=e.originalType,u=e.parentName,p=s(e,["components","mdxType","originalType","parentName"]),d=i(r),g=a,m=d["".concat(u,".").concat(g)]||d[g]||l[g]||o;return r?n.createElement(m,c(c({ref:t},p),{},{components:r})):n.createElement(m,c({ref:t},p))}));function g(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=r.length,c=new Array(o);c[0]=d;var s={};for(var u in t)hasOwnProperty.call(t,u)&&(s[u]=t[u]);s.originalType=e,s.mdxType="string"==typeof e?e:a,c[1]=s;for(var i=2;i<o;i++)c[i]=r[i];return n.createElement.apply(null,c)}return n.createElement.apply(null,r)}d.displayName="MDXCreateElement"},2257:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>u,contentTitle:()=>c,default:()=>l,frontMatter:()=>o,metadata:()=>s,toc:()=>i});var n=r(7462),a=(r(7294),r(3905));const o={sidebar_label:"Quickstart"},c="\ud83d\ude80\xa0Quickstart",s={unversionedId:"quickstart",id:"quickstart",title:"\ud83d\ude80\xa0Quickstart",description:"In <5mins, learn how to access & manage OAuth tokens for any API, using Github as an example. Ready? Go! \u23f0",source:"@site/docs/quickstart.md",sourceDirName:".",slug:"/quickstart",permalink:"/quickstart",draft:!1,editUrl:"https://github.com/nangohq/nango/tree/main/docs/docs/quickstart.md",tags:[],version:"current",frontMatter:{sidebar_label:"Quickstart"},sidebar:"nango",previous:{title:"Introduction",permalink:"/"},next:{title:"Step-by-step guide",permalink:"/reference/guide"}},u={},i=[],p={toc:i};function l(e){let{components:t,...r}=e;return(0,a.kt)("wrapper",(0,n.Z)({},p,r,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("h1",{id:"quickstart"},"\ud83d\ude80\xa0Quickstart"),(0,a.kt)("p",null,"In <5mins, learn how to access & manage OAuth tokens for any API, using Github as an example. Ready? Go! \u23f0"),(0,a.kt)("p",null,"First, clone and start Nango:"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"git clone https://github.com/NangoHQ/quickstart.git && cd quickstart\n")),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"docker compose up # Keep the tab open\n")),(0,a.kt)("p",null,"In a new tab, add any Github OAuth App to Nango (optionally ",(0,a.kt)("a",{parentName:"p",href:"https://docs.github.com/en/developers/apps/building-oauth-apps/creating-an-oauth-app"},"register your own Github OAuth App"),"):"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},'npx nango config:create github-dev github 57876b21174fed02b905 e43242c9a67fa06141e8d219c2364283d14f9ad1 "user,public_repo"\n')),(0,a.kt)("p",null,"Authorize Github on this ",(0,a.kt)("a",{parentName:"p",href:"https://docs.nango.dev/demo/github"},"example page"),". Nango will securely retrieve, store and refresh OAuth credentials. Now try:"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"npx nango token:get 1 github-dev\n")),(0,a.kt)("p",null,"Congrats \ud83e\udd73 You have a fresh token to access the Github API! Let's make sure it works (\u2757\ufe0freplace ",(0,a.kt)("inlineCode",{parentName:"p"},"TOKEN"),"):"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},'curl -XGET -G "https://api.github.com/users/bastienbeurier/repos" \\\n    -H "Authorization: Bearer TOKEN"\n')),(0,a.kt)("p",null,"(In practice, you should use our ",(0,a.kt)("a",{parentName:"p",href:"https://docs.nango.dev/reference/guide#node-sdk"},"backend SDKs")," to fetch tokens from your codebase.)"),(0,a.kt)("p",null,"Wanna go live? Go through the more detailed ",(0,a.kt)("a",{parentName:"p",href:"/reference/guide"},"Step-By-Step Guide"),". You can ",(0,a.kt)("a",{parentName:"p",href:"category/deploy-nango-sync-open-source"},"self-host Nango")," or use ",(0,a.kt)("a",{parentName:"p",href:"cloud"},"Nango Cloud"),"."))}l.isMDXComponent=!0}}]);