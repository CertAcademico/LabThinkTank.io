import { useEffect, useState } from 'react'

function App() {

  const [missions, setMissions] = useState([])
  const [iocFeed, setIocFeed] = useState([])

  useEffect(() => {

    fetch("http://127.0.0.1:8000/missions")
      .then(res => res.json())
      .then(data => setMissions(data))

    fetch("http://127.0.0.1:8000/ioc-feed")
      .then(res => res.json())
      .then(data => setIocFeed(data))

  }, [])

  return (

    <div className="min-h-screen bg-slate-950 text-white p-8">

      <div className="mb-10">

        <h1 className="text-5xl font-bold mb-2">
          CTI-Lab
        </h1>

        <p className="text-slate-400">
          Cyber Threat Intelligence Platform
        </p>

      </div>

      <div className="grid grid-cols-3 gap-6">

        {/* Missions */}

        <div className="col-span-2">

          <h2 className="text-2xl font-semibold mb-4">
            Active Missions
          </h2>

          <div className="space-y-4">

            {
              missions.map(mission => (

                <div
                  key={mission.id}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg"
                >

                  <div className="flex justify-between items-center">

                    <div>

                      <h3 className="text-xl font-bold">
                        {mission.title}
                      </h3>

                      <p className="text-slate-400">
                        Difficulty: {mission.difficulty}
                      </p>

                    </div>

                    <div className="bg-blue-500/20 text-blue-400 px-3 py-1 rounded-lg">
                      ACTIVE
                    </div>

                  </div>

                </div>

              ))
            }

          </div>

        </div>

        {/* IOC Feed */}

        <div>

          <h2 className="text-2xl font-semibold mb-4">
            IOC Feed
          </h2>

          <div className="space-y-4">

            {
              iocFeed.map((ioc, index) => (

                <div
                  key={index}
                  className="bg-slate-900 border border-red-900 rounded-xl p-5"
                >

                  <p className="text-red-400 font-bold mb-2">
                    {ioc.severity.toUpperCase()}
                  </p>

                  <p className="break-all text-sm">
                    {ioc.ioc}
                  </p>

                </div>

              ))
            }

          </div>

        </div>

      </div>

    </div>
  )
}

export default App
