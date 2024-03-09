domain "nic.cz" do
  rdap do
    status :server_transfer_prohibited
    registrar "REG-CZNIC"
    registrant "CZ-NIC"
    expires "2027-03-14"
  end

  dns do
    dnssec :valid
    nameservers ["a.ns.nic.cz", "b.ns.nic.cz", "d.ns.nic.cz"]
    record "www", :a, "217.31.205.50"
    record "www", :aaaa, "2001:1488:0:3::2"
  end
end

ipv4 "217.31.205.50" do
  ptr "www.nic.cz"
  tcp 80 do
    status :open
  end
  https 443 do
    host "www.nic.cz"
    server "nginx"
    status_code 200
    cert_sn "04E732C227971E1E92114CE4E26657CD6258"
  end
end
