package http

// FrontendPattern serves the single-page app, which routes every page itself
// and shows the sign-in card to anyone signed out. Mount it public: it is the
// app's one public subtree.
const FrontendPattern = "GET /"
