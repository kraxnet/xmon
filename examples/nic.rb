describe "nic.cz", type: :domain do
  describe :rdap do
    status :server_transfer_prohibited
    registrar "REG-CZNIC"
    registrant "CZ-NIC"
    expires "2027-03-14"
  end

  describe :dns do
    dnssec :valid
    nameservers ["a.ns.nic.cz", "b.ns.nic.cz", "d.ns.nic.cz"]
    record "www", :a, "217.31.205.50"
    record "www", :aaaa, "2001:1488:0:3::2"
  end
end

describe "217.31.205.50", type: :ipv4 do
  port 80, type: :tcp do
    status :open
  end
  port 443, type: :tcp, protocol: :https do
    host "www.nic.cz"
    server "nginx"
    status_code 200
    cert_sn "04E732C227971E1E92114CE4E26657CD6258"
  end
end
