import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            { name: 'vendor-reactflow', test: /node_modules\/(reactflow|@reactflow)\// },
            { name: 'vendor-recharts', test: /node_modules\/recharts\// },
            { name: 'vendor-jspdf', test: /node_modules\/jspdf\// },
            { name: 'vendor-html2canvas', test: /node_modules\/html2canvas\// },
            { name: 'vendor-xlsx', test: /node_modules\/xlsx\// },
            { name: 'vendor-dompurify', test: /node_modules\/dompurify\// },
          ],
        },
      },
    },
  },
  server: {
    allowedHosts: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
