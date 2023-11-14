from networkx import DiGraph
from pandas import DataFrame


def get_cert_property(df: DataFrame, cert_id: int, column: str) -> str:
    if column not in df.columns:
        raise ValueError(f"Dataset does not have column '{column}'")

    sub_df = df[df["cert_id"] == int(cert_id)]

    if not sub_df.shape[0]:  # Certificate is not in the dataset
        raise ValueError(f"Cert ID: {cert_id} not in dataset")

    if sub_df.shape[0] > 1:  # There are more than one occurence with same ID
        raise ValueError(f"Error Cert ID: {cert_id} has {sub_df.shape[0]} occurrences.")

    return sub_df.iloc[0][column]


def get_fips_cert_references_graph(
    df: DataFrame, cert_id: int, colour_mapper: dict[str, str]
) -> tuple[DiGraph, list[str]]:
    if cert_id not in df["cert_id"].unique():
        raise ValueError(f"Cert ID: {cert_id} is not in the dataset")

    cert_id_series = df[df["cert_id"] == cert_id].iloc[0]
    colour_map = [colour_mapper["chosen_cert_colour"]]
    graph = DiGraph()
    graph.add_node(cert_id)

    # Display which certificates are directly referenced by the chosen certificate
    for referenced_cert_id in cert_id_series["module_directly_referencing"]:
        graph.add_node(referenced_cert_id)
        graph.add_edge(cert_id, referenced_cert_id)
        colour_map.append(colour_mapper["referencing_colour"])

    # Display which certificates are directly referencing the chosen certificate
    for referencing_cert_id in cert_id_series["module_directly_referenced_by"]:
        graph.add_node(referencing_cert_id)
        graph.add_edge(referencing_cert_id, cert_id)
        colour_map.append(colour_mapper["referenced_colour"])

    return graph, colour_map


def get_most_referenced_cert_graph(df: DataFrame, status_colour_mapper: dict[str, str]) -> tuple[DiGraph, list[str]]:
    graph = DiGraph()
    colour_map = []
    max_referenced_by_num = df["incoming_direct_references_count"].max()
    most_referenced_certificate = df[df["incoming_direct_references_count"] == max_referenced_by_num].iloc[0]

    origin_cert_id: int = most_referenced_certificate["cert_id"]
    origin_cert_status: str = most_referenced_certificate["status"]
    graph.add_node(origin_cert_id)
    colour_map.append(status_colour_mapper[origin_cert_status])

    for cert_id_str in most_referenced_certificate["module_directly_referenced_by"]:
        cert_id_int = int(cert_id_str)
        graph.add_node(cert_id_int)
        graph.add_edge(cert_id_int, origin_cert_id)
        cert_status: str = get_cert_property(df, cert_id_int, "status")
        colour_map.append(status_colour_mapper[cert_status])

    return graph, colour_map


def get_most_referencing_cert_graph(df: DataFrame, status_colour_mapper: dict[str, str]) -> tuple[DiGraph, list[str]]:
    graph = DiGraph()
    colour_map = []
    max_referencing_num = df["outgoing_direct_references_count"].max()
    most_referencing_cert = df[df["outgoing_direct_references_count"] == max_referencing_num].iloc[0]
    origin_cert_id = most_referencing_cert["cert_id"]
    origin_cert_status = most_referencing_cert["status"]
    colour_map.append(status_colour_mapper[origin_cert_status])

    for cert_id_str in most_referencing_cert["module_directly_referencing"]:
        cert_id_int = int(cert_id_str)
        graph.add_node(cert_id_int)
        graph.add_edge(origin_cert_id, cert_id_int)
        cert_status: str = get_cert_property(df, cert_id_int, "status")
        colour_map.append(status_colour_mapper[cert_status])

    return graph, colour_map
