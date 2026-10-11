import { BrowserRouter, Route, Routes } from "react-router"

import { Layout } from "@/components/Layout"
import { Toaster } from "@/components/ui/sonner"
import { NotFound } from "@/pages/NotFound"

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Layout>
      <Toaster />
    </BrowserRouter>
  )
}
