from packetbeat import BaseTest


class Test(BaseTest):

    def test_mssql_15x(self):
        self.render_config_template(
            mssql_ports=[1433],
            mssql_send_response=True
        )
        self.run_packetbeat(pcap="mssql_15x_login_and_select.pcap",
                            debug_selectors=["mssql,tcp,publish"])

        objs = self.read_output()
        assert all([o["server.port"] == 1433 for o in objs])
        
        assert len(objs) == 4
        assert objs[0]["status"] == "OK"
        assert objs[0]["mssql.version"] == 15
        assert objs[0]["mssql.db_name"] == "master"

        assert objs[1]["method"] == "SET"
        assert objs[3]["method"] == "SELECT"
        assert objs[3]["mssql.num_rows"] == 1
        assert objs[3]["mssql.num_fields"] == 2
        assert objs[3]["response"] != None



