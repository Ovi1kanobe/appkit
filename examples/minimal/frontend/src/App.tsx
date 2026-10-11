import { BrowserRouter, Route, Routes } from "react-router"

import { Layout } from "@/components/Layout"
import { Toaster } from "@/components/ui/sonner"
import { Dashboard } from "@/pages/Dashboard"
import { Home } from "@/pages/Home"
import { NotFound } from "@/pages/NotFound"
import { Settings } from "@/pages/Settings"

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Layout>
      <Toaster />
    </BrowserRouter>
  )
}
