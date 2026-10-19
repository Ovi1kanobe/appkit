import { BrowserRouter, Route, Routes } from "react-router"

import { Layout } from "@/components/Layout"
import { Toaster } from "@/components/ui/sonner"
import { Account } from "@/pages/Account"
import { NotFound } from "@/pages/NotFound"

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/account" element={<Account />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Layout>
      <Toaster />
    </BrowserRouter>
  )
}
